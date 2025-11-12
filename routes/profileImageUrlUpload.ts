/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

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
        // Validate URL format and protocol
        let urlObject
        try {
          urlObject = new URL(url)
        } catch (error) {
          res.status(400).json({ error: 'Invalid URL format' })
          return
        }

        // Only allow http and https protocols
        if (urlObject.protocol !== 'http:' && urlObject.protocol !== 'https:') {
          res.status(400).json({ error: 'Only HTTP and HTTPS protocols are allowed' })
          return
        }

        const hostname = urlObject.hostname.toLowerCase()

        // Comprehensive blocklist for private/internal addresses
        const isPrivateOrLocal = 
          hostname === 'localhost' ||
          hostname === '127.0.0.1' ||
          hostname === '::1' ||
          hostname === '0.0.0.0' ||
          hostname.startsWith('127.') ||
          hostname.startsWith('10.') ||
          hostname.startsWith('192.168.') ||
          hostname.startsWith('169.254.') ||
          hostname.match(/^172\.(1[6-9]|2\d|3[0-1])\./) ||
          hostname.endsWith('.local') ||
          hostname.endsWith('.localhost')

        if (isPrivateOrLocal) {
          res.status(400).json({ error: 'Access to private or local addresses is not allowed' })
          return
        }

        // Now proceed with fetch
        try {
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          await UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { 
            return await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` }) 
          }).catch((error: Error) => { next(error) })
        } catch (error) {
          // For network/fetch errors, do NOT use the URL directly
          // Just return an error instead
          res.status(500).json({ error: 'Failed to retrieve image from URL' })
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