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
        const isPrivateAddress = (addr: string): boolean => {
          // Handle IPv4-mapped IPv6 addresses like ::ffff:192.168.0.1
          if (addr.startsWith('::ffff:')) addr = addr.split('::ffff:')[1]
          const ver = net.isIP(addr)
          if (ver === 4) {
            const parts = addr.split('.').map(Number)
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
            return false
          }
          return false
        }

        const validateUrlHostIsPublic = async (targetUrl: string): Promise<URL> => {
          let parsed: URL
          try {
            parsed = new URL(targetUrl)
          } catch (err) {
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
          }
          return parsed
        }

        try {
          // Validate the provided URL's host before fetching
          const parsed = await validateUrlHostIsPublic(url)

          // Use the validated parsed URL instead of the raw user input
          const response = await fetch(parsed.href, { redirect: 'follow' })
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }

          // Validate the final URL after redirects to prevent DNS rebinding
          const finalUrl = response.url ?? parsed.href
          await validateUrlHostIsPublic(finalUrl)

          // Validate content type is an image
          const contentType = response.headers.get('content-type') || ''
          if (!contentType.startsWith('image/')) {
            throw new Error('URL did not return an image content-type')
          }

          // Determine file extension from content-type with fallback
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
          // Do not store unvalidated URLs - return error instead
          logger.error(`Failed to fetch and validate profile image: ${utils.getErrorMessage(error)}`)
          next(new Error('Unable to fetch profile image from provided URL. Please ensure the URL is valid and publicly accessible.'))
          return
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
