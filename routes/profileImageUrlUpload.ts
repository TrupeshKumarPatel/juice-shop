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
<<<<<<< Updated upstream
        const isPrivateAddress = (addr: string) => {
          // handle IPv4-mapped IPv6 like ::ffff:192.168.0.1
=======
        const isPrivateAddress = (addr: string): boolean => {
          // Handle IPv4-mapped IPv6 addresses like ::ffff:192.168.0.1
>>>>>>> Stashed changes
          if (addr.startsWith('::ffff:')) addr = addr.split('::ffff:')[1]
          const ver = net.isIP(addr)
          if (ver === 4) {
            const parts = addr.split('.').map(Number)
<<<<<<< Updated upstream
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
=======
            // 10.0.0.0/8
            if (parts[0] === 10) return true
            // 127.0.0.0/8 (loopback)
            if (parts[0] === 127) return true
            // 169.254.0.0/16 (link-local)
            if (parts[0] === 169 && parts[1] === 254) return true
            // 172.16.0.0/12 (private)
            if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true
            // 192.168.0.0/16 (private)
            if (parts[0] === 192 && parts[1] === 168) return true
            // 0.0.0.0/8 (current network)
            if (parts[0] === 0) return true
            // 100.64.0.0/10 (carrier-grade NAT)
            if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true
            return false
          } else if (ver === 6) {
            const lower = addr.toLowerCase()
            // ::1 (loopback)
            if (lower === '::1') return true
            // fe80::/10 (link-local)
            if (lower.startsWith('fe80')) return true
            // fc00::/7 (unique local)
            if (lower.startsWith('fc') || lower.startsWith('fd')) return true
>>>>>>> Stashed changes
            return false
          }
          return false
        }

<<<<<<< Updated upstream
        const validateUrlHostIsPublic = async (targetUrl: string) => {
=======
        const validateUrlHostIsPublic = async (targetUrl: string): Promise<URL> => {
>>>>>>> Stashed changes
          let parsed: URL
          try {
            parsed = new URL(targetUrl)
          } catch (err) {
<<<<<<< Updated upstream
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
=======
            throw new Error('Invalid URL format')
          }
          // Only allow http and https protocols
          if (!['http:', 'https:'].includes(parsed.protocol)) {
            throw new Error('Only HTTP(S) URLs are allowed')
          }
          const hostname = parsed.hostname
          // Block localhost explicitly
          if (!hostname || hostname === 'localhost') {
            throw new Error('Localhost is not allowed')
          }
          // Resolve DNS and check all returned addresses
          const records = await dns.promises.lookup(hostname, { all: true }).catch(() => {
            throw new Error('DNS lookup failed')
          })
          if (!records || records.length === 0) {
            throw new Error('DNS lookup returned no addresses')
          }
          for (const r of records) {
            if (isPrivateAddress(r.address)) {
              throw new Error('URL resolves to a private or internal address')
            }
>>>>>>> Stashed changes
          }
          return parsed
        }

        try {
<<<<<<< Updated upstream
          // validate the provided URL's host first
=======
          // Validate the provided URL's host before fetching
>>>>>>> Stashed changes
          const parsed = await validateUrlHostIsPublic(url)

          const response = await fetch(url, { redirect: 'follow' })
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }

<<<<<<< Updated upstream
          // ensure the final fetch location (after redirects) is also public
          const finalUrl = response.url || parsed.href
          await validateUrlHostIsPublic(finalUrl)

=======
          // Validate the final URL after redirects to prevent DNS rebinding
          const finalUrl = response.url || parsed.href
          await validateUrlHostIsPublic(finalUrl)

          // Validate content type is an image
>>>>>>> Stashed changes
          const contentType = response.headers.get('content-type') || ''
          if (!contentType.startsWith('image/')) {
            throw new Error('URL did not return an image content-type')
          }

<<<<<<< Updated upstream
          // pick extension from content-type with fallback to url path
=======
          // Determine file extension from content-type with fallback
>>>>>>> Stashed changes
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
