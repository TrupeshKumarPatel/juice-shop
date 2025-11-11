export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        // Validate URL BEFORE the try block
        try {
          const urlObject = new URL(url)
          const hostname = urlObject.hostname.toLowerCase()
          
          if (hostname === 'localhost' || 
              hostname === '127.0.0.1' || 
              hostname === '::1' || 
              hostname === '169.254.169.254' ||
              hostname.startsWith('169.254.') ||
              hostname.endsWith('.local') || 
              hostname.match(/^192\.168\.\d{1,3}\.\d{1,3}$/) || 
              hostname.match(/^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/) || 
              hostname.match(/^172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}$/)) {
            // Don't throw - send error response directly
            res.status(400).json({ error: 'Invalid URL: Local or private addresses are not allowed' })
            return
          }
        } catch (error) {
          // Invalid URL format
          res.status(400).json({ error: 'Invalid URL format' })
          return
        }

        // Now try to fetch - this is in a separate try-catch
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
          // Only for fetch/network errors - still use URL directly as fallback
          try {
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