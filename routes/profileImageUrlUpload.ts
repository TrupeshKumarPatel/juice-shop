/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'
import dns from 'node:dns'
import net from 'node:net'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        const isPrivateAddress = (addr: string) => {
          // handle IPv4-mapped IPv6 like ::ffff:192.168.0.1
          if (addr.startsWith('::ffff:')) addr = addr.split('::ffff:')[1]
          const ver = net.isIP(addr)
          if (ver === 4) {
            const parts = addr.split('.').map(Number)
            if (parts[0] === 10) return true
            if (parts[0] === 127) return true
            if (parts[0] === 169 && parts[1] === 254) return true
            if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true
            if (parts[0] === 192 && parts[1] === 168) return true
            return false
          } else if (ver === 6) {
            // common IPv6 private/loopback checks
            const lower = addr.toLowerCase()
            if (lower === '::1') return true
            if (lower.startsWith('fe80') || lower.startsWith('fc') || lower.startsWith('fd')) return true
            return false
          }
          return false
        }

        const validateUrlHostIsPublic = async (targetUrl: string) => {
          let parsed: URL
          try {
            parsed = new URL(targetUrl)
          } catch (err) {
            throw new Error('Invalid URL')
          }
          if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('Only http(s) URLs are allowed')
          const hostname = parsed.hostname
          if (!hostname || hostname === 'localhost') throw new Error('Localhost is not allowed')
          // resolve DNS and ensure none of the addresses are private
          const records = await dns.promises.lookup(hostname, { all: true }).catch(() => { throw new Error('DNS lookup failed') })
          if (!records || records.length === 0) throw new Error('DNS lookup returned no addresses')
          for (const r of records) {
            if (isPrivateAddress(r.address)) throw new Error('Resolved address is in a private range')
          }
          return parsed
        }

        try {
          // validate the provided URL's host first
          const parsed = await validateUrlHostIsPublic(url)

          const response = await fetch(url, { redirect: 'follow' })
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }

          // ensure the final fetch location (after redirects) is also public
          const finalUrl = response.url || parsed.href
          await validateUrlHostIsPublic(finalUrl)

          const contentType = response.headers.get('content-type') || ''
          if (!contentType.startsWith('image/')) {
            throw new Error('URL did not return an image content-type')
          }

          // pick extension from content-type with fallback to url path
          let ext = 'jpg'
          if (contentType.includes('image/png')) ext = 'png'
          else if (contentType.includes('image/svg')) ext = 'svg'
          else if (contentType.includes('image/gif')) ext = 'gif'
          else if (contentType.includes('jpeg') || contentType.includes('jpg')) ext = 'jpg'
          else {
            const pathExt = parsed.pathname.split('.').slice(-1)[0].toLowerCase()
            if (['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(pathExt)) ext = pathExt
          }

          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          await UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` }) }).catch((error: Error) => { next(error) })
        } catch (error) {
          try {
            // If fetch or validation fails, do NOT perform a server-side fetch.
            // Keep the previous fallback behavior of storing the URL so the client may load it,
            // but do not attempt to fetch unsafe/internal addresses on the server.
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
