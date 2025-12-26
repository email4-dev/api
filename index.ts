import { challenge, verify } from './captcha'
import { getDomain } from 'tldjs'
import crypto from 'crypto'
import PocketBase from 'pocketbase'
import Valkey from 'iovalkey'
import * as Minio from 'minio'
import { verifyDomain } from './dns'
import { serve, type BunRequest } from 'bun'
import { Eta } from "eta"
import { join } from "path"
import { createReadStream, createWriteStream, unlinkSync } from 'fs'
import Archiver from 'archiver'
import { tmpdir } from 'os'
import { stat } from 'fs/promises'

const db = new PocketBase(Bun.env.POCKETBASE_URL)

db.autoCancellation(false)

const file = Bun.file('package.json')
const content = await file.text()
const match = content.match(/"version"\s*:\s*"([^"]+)"/)
const version = match ? match[1] : '0.0.0'
const eta = new Eta({
  views: join(import.meta.dir, "views"),
  cache: Bun.env.NODE_ENV === "production"
})

console.log(`Email4.dev API v${version} starting...`)

await db.collection('_superusers').authWithPassword(
    Bun.env.POCKETBASE_EMAIL!,
    Bun.env.POCKETBASE_PASS!,
)

if(!db.authStore.isValid) {
    throw 'Pocketbase authentication failed!'
}

const valkey = new Valkey(6379, Bun.env.VALKEY_URL!)
const hasher = new Bun.CryptoHasher("sha256")
const bucket = Bun.env.S3_BUCKET!
const minio = new Minio.Client({
    endPoint: Bun.env.S3_URL!,
    port: parseInt(Bun.env.S3_PORT!),
    accessKey: Bun.env.S3_ACCESS_KEY!,
    secretKey: Bun.env.S3_SECRET_KEY!,
    useSSL: (Bun.env.S3_SSL! === "true"),
    region: Bun.env.S3_REGION!,
})

const bucketExists = await minio.bucketExists(bucket)
if (!bucketExists) {
  throw 'S3 bucket missing!'
}

valkey.on("error", (err) => {
    if(err) {
        throw err
    } else {
        throw 'Valkey disconnected'
    }
})

process.on("beforeExit", async () => {
    console.log('Email4.dev API exiting gracefully...')
    db.authStore.clear()
    await valkey.quit()
})

const cors = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'content-type'
}

const sendResponse = (type: string, status: number, payload: any, error: boolean = false) => {
    if(type === 'json') {
        return error ? Response.json({ error: true, message: payload }, { status, headers: cors }) : Response.json(payload, { status, headers: cors })
    } else {
        return new Response(payload, { status, headers: cors })
    }
}

const sendRedirect = (url: string, message: string, key: string = 'result') => {
    return Response.redirect(`${url}?${key}=${encodeURIComponent(message)}`, 303)
}

const sendError = (type: string, status: number, message: string, redirect: string | null = null) => {
    if(redirect !== null && type !== 'json') {
        return sendRedirect(redirect, message, 'error')
    } else {
        return sendResponse(type, status, message, true)
    }
}

const getRequestType = (req:BunRequest|Request): null | 'json' | 'form' => {
    const contentType = req.headers.get('content-type')
    if(contentType === 'application/json') return 'json'
    if(contentType === 'application/x-www-form-urlencoded') return 'form'
    if(contentType?.startsWith('multipart/form-data')) return 'form'
    return null
}

const generateOTP = () => {
  const array = new Uint32Array(1)
  crypto.getRandomValues(array)
  return (array[0] % 900000 + 100000).toString()
}

const byteValueNumberFormatter = Intl.NumberFormat("en", {
  notation: "compact",
  style: "unit",
  unit: "byte",
  unitDisplay: "narrow",
})

serve({
  port: 3000,
  routes : {
    '/altcha/:form_id': async (req:BunRequest) => {
        if(req.method !== "GET") {
            return sendError('form', 405, 'HTTP method not supported')
        }
        if(Bun.env.DEBUG == "true") console.debug('Altcha init', req)
        // @ts-expect-error
        const form_id: string = req.params.form_id
        if(!form_id || !form_id.length) {
            return sendError('form', 401, 'Bad Request')
        }
        const origin = req.headers.get('origin') || ''
        let { handler_id, error } = await validateForm(form_id, origin)
        if(error) {
            console.warn('Altcha error', form_id, error?.message)
            return sendError('json', error?.status, error.message)
        }
        const hmac = await challenge(valkey, handler_id)
        if(Bun.env.DEBUG == "true") {
            console.debug(`Sending response `, hmac, `with expiry at `, new Date(Date.now() + (parseInt(Bun.env.CAPTCHA_EXPIRE!) || 60 * 1000)).toUTCString(), `based on CAPTCHA_EXPIRE `, Bun.env.CAPTCHA_EXPIRE)
        }
        return Response.json(hmac, { headers: {
            ...cors,
            Expires: new Date(Date.now() + (parseInt(Bun.env.CAPTCHA_EXPIRE!) || 60 * 1000)).toUTCString()
        }})
    },
    '/attachments/:hex': async (req:BunRequest) => {
        if(!["GET", "POST"].includes(req.method)) {
            return sendError('form', 405, 'Request method not supported')
        }
        if(Bun.env.DEBUG == "true") console.debug('Attachments init', req)
        // @ts-expect-error
        const hex: string = req.params.hex
        if(!hex || !hex.length) {
            return new Response(eta.render('error', {
                pageTitle: 'Error',
                errorNumber: 401,
                errorMessage: 'Resource id missing'
            }), {
                headers: { "Content-Type": "text/html" },
                status: 401
            })
        }
        const exists = await valkey.exists(`attachments:${hex}`)
        if(exists === 0) {
            if(Bun.env.DEBUG == "true") console.warn('Download expired or missing', hex)
            return new Response(eta.render('error', {
                pageTitle: 'Error',
                errorNumber: 404,
                errorMessage: 'Download expired or missing'
            }), {
                headers: { "Content-Type": "text/html" },
                status: 404
            })
        }
        const download = await valkey.hgetall(`attachments:${hex}`)
        const form = await db.collection('forms').getOne(download.form_id)
        if(form.retention_limit > 0 && form.retention_type === 'downloads') {
            if(download.count >= form.retention_limit) {
                if(Bun.env.DEBUG == "true") console.debug('Download limit reached', download)
                return new Response(eta.render('error', {
                    pageTitle: 'Error',
                    errorNumber: 403,
                    errorMessage: 'Download limit reached'
                }), {
                    headers: { "Content-Type": "text/html" },
                    status: 403
                })
            }
        }
        let sessionId = req.cookies.get("session")
        if(!sessionId) {
            sessionId = crypto.randomUUID()
            req.cookies.set("session", sessionId, {
                maxAge: 60 * 60 * 24, // 1 day
                httpOnly: true,
                secure: Bun.env.API_URL?.startsWith('https')
            })
        }
        if(form.protect_attachments) {
            switch(req.method) {
                case "GET":
                    const otpExists = await valkey.exists(`otp:${sessionId}`)
                    const now = Date.now()
                    let otpTtl = 600
                    let otpExpiry = now + otpTtl * 1000
                    if(otpExists) {
                        otpExpiry = await valkey.expiretime(`otp:${sessionId}`)
                    } else {
                        const otp = generateOTP()
                        await valkey.set(`otp:${sessionId}`, otp)
                        await valkey.expire(`otp:${sessionId}`, otpTtl) // 10 minutes
                        const stream_id = await valkey.xadd('messages', '*', 'hex', 'otp', 'form_id', download.form_id, 'fields', JSON.stringify([{ key: 'otp', value: otp }]), 'attachment_count', 0)
                        if(!stream_id) {
                            console.warn('Could not add otp notification to queue')
                            return new Response(eta.render('error', {
                                pageTitle: 'Error',
                                errorNumber: 500,
                                errorMessage: 'Could not send OTP'
                            }), {
                                headers: { "Content-Type": "text/html" },
                                status: 500
                            })
                        }
                    }
                    return new Response(eta.render('otp', {
                        pageTitle: 'Authorization Required',
                        error: false,
                        otpExpiry,
                        action: req.method,
                    }), {
                        headers: { "Content-Type": "text/html" }
                    })
                case "POST":
                    if(getRequestType(req) !== 'form') {
                        return sendError('form', 405, 'Mime not supported')
                    }
                    const formData = await req.formData()
                    const userOtp = formData.get('otp')?.toString()
                    const savedOtp = await valkey.get(`otp:${sessionId}`)
                    const action = formData.get('action')?.toString()
                    if(userOtp !== savedOtp) {
                        const otpExpiry = await valkey.expiretime(`otp:${sessionId}`)
                        return new Response(eta.render('otp', {
                            pageTitle: 'Error',
                            error: true,
                            otpExpiry,
                            action,
                        }), {
                            headers: { "Content-Type": "text/html" },
                            status: 403
                        })
                    }
                    await valkey.del(`otp:${sessionId}`)
            }
        }

        const fileData = JSON.parse(download.files)

        const ttl = await valkey.ttl(`attachments:${hex}`)
        let expiry = null
        if(ttl > 0) {
            const now = Date.now()
            expiry = now + ttl * 1000
        }

        return new Response(await eta.renderAsync('download', {
            pageTitle: 'Download',
            downloadUrl: `${Bun.env.API_URL}download/${hex}`,
            deleteUrl: `${Bun.env.API_URL}attachments/${hex}/delete`,
            limit: form.retention_limit > 0 && form.retention_type === 'downloads' ? form.retention_limit - parseInt(download.count) : null,
            expiry,
            canDelete: form.recipient_can_delete_attachments,
            files: await Promise.all(fileData.map(async (f:MessageAttachment) => {
                return {
                    name: f.filename,
                    size: byteValueNumberFormatter.format((await minio.statObject(bucket, f.key)).size)
                }
            })),
        }), {
            headers: { "Content-Type": "text/html" }
        })
    },
    '/attachments/:hex/delete': async (req:BunRequest) => {
        if(getRequestType(req) !== 'form' && req.method !== "POST") {
            return sendError('form', 405, 'HTTP method not supported')
        }
        if(Bun.env.DEBUG == "true") console.debug('Deleting Attachments init', req)
        // @ts-expect-error
        const hex: string = req.params.hex
        if(!hex || !hex.length) {
            return new Response(eta.render('error', {
                pageTitle: 'Error',
                errorNumber: 401,
                errorMessage: 'Resource id missing'
            }), {
                headers: { "Content-Type": "text/html" },
                status: 401
            })
        }
        const exists = await valkey.exists(`attachments:${hex}`)
        if(exists === 0) {
            if(Bun.env.DEBUG == "true") console.warn('Download expired or missing', hex)
            return new Response(eta.render('error', {
                pageTitle: 'Error',
                errorNumber: 404,
                errorMessage: 'Download expired or missing'
            }), {
                headers: { "Content-Type": "text/html" },
                status: 404
            })
        }
        const download = await valkey.hgetall(`attachments:${hex}`)
        const form = await db.collection('forms').getOne(download.form_id)
        if(!form.recipient_can_delete_attachments) {
            return new Response(eta.render('error', {
                pageTitle: 'Error',
                errorNumber: 403,
                errorMessage: 'Recipients are not allowed to delete attachments'
            }), {
                headers: { "Content-Type": "text/html" },
                status: 403
            })
        }
        if(form.retention_limit > 0 && form.retention_type === 'downloads') {
            if(download.count >= form.retention_limit) {
                if(Bun.env.DEBUG == "true") console.debug('Download limit reached', download)
                return new Response(eta.render('error', {
                    pageTitle: 'Error',
                    errorNumber: 403,
                    errorMessage: 'Download limit reached'
                }), {
                    headers: { "Content-Type": "text/html" },
                    status: 403
                })
            }
        }
        let sessionId = req.cookies.get("session")
        if(!sessionId) {
            sessionId = crypto.randomUUID()
            req.cookies.set("session", sessionId, {
                maxAge: 60 * 60 * 24, // 1 day
                httpOnly: true,
                secure: Bun.env.API_URL?.startsWith('https')
            })
        }
        const formData = await req.formData()
        const userOtp = formData.get('otp')?.toString()
        if(userOtp) {
            const savedOtp = await valkey.get(`otp:${sessionId}`)
            if(userOtp !== savedOtp) {
                const otpExpiry = await valkey.expiretime(`otp:${sessionId}`)
                return new Response(eta.render('otp', {
                    pageTitle: 'Error',
                    error: true,
                    otpExpiry,
                    action: 'DELETE',
                }), {
                    headers: { "Content-Type": "text/html" },
                    status: 403
                })
            }
            await valkey.del(`otp:${sessionId}`)
            const files:MessageAttachment[] = JSON.parse(download.files) || []
            if(files.length) await minio.removeObjects(bucket, files.map(a => a.key))
            await valkey.del(`attachments:${hex}`)
            return new Response(eta.render('deleted', {
                pageTitle: 'Files Deleted Successfully',
            }), {
                headers: { "Content-Type": "text/html" }
            })
        } else {
            const otpExists = await valkey.exists(`otp:${sessionId}`)
            const now = Date.now()
            let otpTtl = 600
            let otpExpiry = now + otpTtl * 1000
            if(otpExists) {
                otpExpiry = await valkey.expiretime(`otp:${sessionId}`)
            } else {
                const otp = generateOTP()
                await valkey.set(`otp:${sessionId}`, otp)
                await valkey.expire(`otp:${sessionId}`, otpTtl) // 10 minutes
                const stream_id = await valkey.xadd('messages', '*', 'hex', 'otp', 'form_id', download.form_id, 'fields', JSON.stringify([{ key: 'otp', value: otp }]), 'attachment_count', 0)
                if(!stream_id) {
                    console.warn('Could not add otp notification to queue')
                    return new Response(eta.render('error', {
                        pageTitle: 'Error',
                        errorNumber: 500,
                        errorMessage: 'Could not send OTP'
                    }), {
                        headers: { "Content-Type": "text/html" },
                        status: 500
                    })
                }
            }
            return new Response(eta.render('otp', {
                pageTitle: 'Authorization Required',
                error: false,
                otpExpiry,
                action: req.method,
            }), {
                headers: { "Content-Type": "text/html" }
            })
        }
    },
    '/download/:hex': async (req:BunRequest) => {
        if(req.method !== "GET" || getRequestType(req) !== 'json') { // this only works via the download page
            return sendError('form', 405, 'HTTP method not supported')
        }
        if(Bun.env.DEBUG == "true") console.debug('Download init', req)
        // @ts-expect-error
        const hex: string = req.params.hex
        if(!hex || !hex.length) {
            return sendError('json', 401, 'Resource id missing')
        }
        const sessionId = req.cookies.get("session")
        if(!sessionId) {
            return sendError('json', 403, 'Cookie missing')
        }
        const exists = await valkey.exists(`attachments:${hex}`)
        if(exists === 0) {
            if(Bun.env.DEBUG == "true") console.warn('Download expired or missing', hex)
            return sendError('json', 404, 'Download expired or missing')
        }
        const download = await valkey.hgetall(`attachments:${hex}`)
        const downloadCount = parseInt(download.count)
        const form = await db.collection('forms').getOne(download.form_id)
        const isRedownload = await valkey.exists(`down:${hex}:${sessionId}`)
        if(!isRedownload) {
            await valkey.hincrby(`attachments:${hex}`, 'count', 1)
            await valkey.setex(`down:${hex}:${sessionId}`, 60 * 60 * 24, 1) // 24 hours
        }
        try {
            const fileData:MessageAttachment[] = JSON.parse(download.files)
            if(fileData.length === 0) {
                if(Bun.env.DEBUG == "true") console.warn('File list empty', download)
                return sendError('json', 404, 'File list empty')
            }
            const timestamp = Date.now()
            if(fileData.length > 1) {
                const zipPath = join(tmpdir(), `attachments-${timestamp}.zip`)
                const output = createWriteStream(zipPath)
                const archive = Archiver('zip', { zlib: { level: 5 } })

                await new Promise(async (resolve, reject) => {
                    archive.pipe(output)
                    
                    // Handle archive errors
                    archive.on('error', err => reject(err))
                    output.on('error', err => reject(err))
                    output.on('close', () => resolve(true))

                    try {
                        for (const file of fileData) {
                            const fileStream = await minio.getObject(bucket, file.key)
                            archive.append(fileStream, { name: file.filename })
                        }
                        await archive.finalize()
                    } catch (err) {
                        reject(err)
                    }
                })

                const fileStream = createReadStream(zipPath)
                const stats = await stat(zipPath)
                // Clean up
                fileStream.on('end', async () => {
                    unlinkSync(zipPath)
                    if(form.retention_limit !== 0 && form.retention_type === 'downloads' && downloadCount === form.retention_limit - 1) {
                        for (const file of fileData) {
                           await minio.removeObject(bucket, file.key)
                        }
                        await valkey.del(`attachments:${hex}`)
                    }
                })
                return new Response(fileStream as any, {
                    headers: {
                        ...cors,
                        'Content-Type': 'application/zip',
                        'Content-Disposition': `attachment; filename="attachments-${timestamp}.zip"`,
                        'Content-Length': `${stats.size}` || '',
                    },
                })
            } else {
                const s3ObjectStats = await minio.statObject(bucket, fileData[0].key)
                const s3Object = await minio.getObject(bucket, fileData[0].key)
                // Clean up
                s3Object.on('close', async () => {
                    if(form.retention_limit !== 0 && form.retention_type === 'downloads' && downloadCount === form.retention_limit - 1) {
                        await minio.removeObject(bucket, fileData[0].key)
                        await valkey.del(`attachments:${hex}`)
                    }
                })
                return new Response(s3Object as any, {
                    headers: {
                        ...cors,
                        'Content-Type': s3ObjectStats.metaData['Content-Type'] || 'application/octet-stream',
                        'Content-Disposition': `attachment; filename="${fileData[0].filename}"`,
                        'Content-Length': `${s3ObjectStats.size}` || '',
                    },
                })
            }
        } catch(error) {
            console.warn('File list corrupted', download)
            return sendError('json', 500, 'File list corrupted')
        }
    },
    '/submit/:form_id': async (req:BunRequest) => {
        const type = getRequestType(req)
        if(req.method !== "POST" || type === null) { // this only works via the download page
            return sendError('form', 405, 'HTTP method not supported')
        }
        // @ts-expect-error
        const form_id: string = req.params.form_id
        if(!form_id || !form_id.length) {
            return sendError(type, 401, 'Bad Request')
        }
        if(Bun.env.DEBUG == "true") console.debug('Form submission', req)
        const formData = type === 'form' ? await req.formData() : await req.json()
        const origin = req.headers.get('origin') || ''
        const { error } = await validateForm(form_id, origin)
        if(error) {
            console.warn('Submission error', form_id, error?.message)
            return sendError('json', error?.status, error.message)
        }
        const form = await db.collection('forms').getOne(form_id, {
            expand: 'handler,handler.domains',
            fields: '*,expand.handler.*,expand.handler.domains.name,expand.handler.domains.verified'
        }).then(data => data).catch(() => null)
        if(!form) {
            console.warn('Form not found:', form_id)
            return sendError(type, 404, 'Form not found')
        }
        // check redirect targets
        let redirectSuccessUrl = form.expand?.handler.redirect_success
        let redirectFailUrl = form.expand?.handler.redirect_fail
        if(!redirectSuccessUrl) {
            const redirSuccess = type === 'form' ? formData.get('redir_success') : formData.redir_success || null
            redirectSuccessUrl = redirSuccess ? redirSuccess : req.headers.get("referer")
        }
        if(!redirectFailUrl) {
            const redirFail = type === 'form' ? formData.get('redir_fail') : formData.redir_fail || null
            redirectFailUrl = redirFail ? redirFail : redirectSuccessUrl ? redirectSuccessUrl : req.headers.get("referer")
        }
        // @ts-expect-error
        const redirectSuccess: Boolean = form.expand?.handler.expand?.domains.some(d => d.name == getDomain(redirectSuccessUrl) && d.verified.includes('ownership'))
        // @ts-expect-error
        const redirectFail: Boolean = form.expand?.handler.expand?.domains.some(d => d.name == getDomain(redirectFailUrl) && d.verified.includes('ownership'))
        if(!redirectSuccess || !redirectFail) {
            console.warn(`Domain doesn't match redirect configuration for form:`, form_id)
            return sendError(type, 400, `Redirect doesn't match domain`, null)
        }
        // check altcha
        if(form.altcha) {
            const altchaData = type === 'form' ? formData.get('altcha') : formData.altcha
            if(!altchaData) {
                console.warn('Altcha field missing in form:', form_id)
                return sendError(type, 403, 'Altcha field missing', redirectFailUrl)
            } else {
                const payload = JSON.parse(atob(altchaData))
                const altchaResult = await verify(valkey, payload, form.handler)
                if(!altchaResult) {
                    console.warn('Altcha mismatch for form:', form_id)
                    return sendError(type, 403, 'Altcha mismatch', redirectFailUrl)
                }
            }
        }
        // check honeypot
        if(form.honeypot.length) {
            const honeypotData = type === 'form' ? formData.get(form.honeypot) : formData[form.honeypot]
            if(!honeypotData) {
                console.warn('Honeypot enabled but not implemented', req)
                return sendError(type, 400, 'Honeypot missing', redirectFailUrl)
            } else {
                if(honeypotData.length) {
                    console.info('Bot detected!', req)
                    return sendError(type, 403, 'Bot detected')
                }
            }
        }
        // init data variables
        const fields:MessageField[] = []
        const attachments:MessageAttachment[] = []
        // skip system fields
        const skipKeys = new Set(['altcha', 'redir_success', 'redir_fail'])
        if(form.honeypot.length) skipKeys.add(form.honeypot)
        // loop fields
        if(type === 'form') {
            for(const key of formData.keys()) {
                if(skipKeys.has(key)) continue
                skipKeys.add(key) // needed since we are looping on potentially "multiple" fields
                const values: string[]|File[] = formData.getAll(key)
                if(values[0] instanceof File) {
                    for(let i=0;i<values.length;i++) {
                        const file = values[i] as File
                        // 20mb default limit
                        if(file.size < (parseInt(Bun.env.ATTACHMENT_LIMIT || "20") * 1024 * 1024)) {
                            const attachment_id = crypto.randomUUID()
                            await minio.putObject(bucket, attachment_id, Buffer.from(await file.arrayBuffer()), file.size, {
                                'Content-Type': file.type,
                                'Attachment-Expiry': Date.now() + getAttachmentExpiry(form.retention_type, form.retention_limit) * 1000
                            })
                            attachments.push({ name: key, key: attachment_id, filename: file.name })
                        } else {
                            console.warn(`Attachment exceeds ${Bun.env.ATTACHMENT_LIMIT || 20}MB`, key)
                        }
                    }
                } else {
                    fields.push({ name: key, value: values.join(', ') })
                }
            }
        } else {
            for(const key of Object.keys(formData)) {
                if(skipKeys.has(key)) continue
                if(formData[key][0].constructor.name === "Object" && Object.hasOwn(formData[key][0], 'filename')) {
                    for(let i=0;i<formData[key].length;i++) {
                        const binary = atob(formData[key][i].filedata)
                        const bytes = new Uint8Array(binary.length)
                        for (let i = 0; i < binary.length; i++) {
                            bytes[i] = binary.charCodeAt(i)
                        }
                        const file = new File([bytes], formData[key][i].filename)
                        // 20mb default limit
                        if(file.size < (parseInt(Bun.env.ATTACHMENT_LIMIT || "20") * 1024 * 1024)) {
                            const attachment_id = crypto.randomUUID()
                            await minio.putObject(bucket, attachment_id, Buffer.from(await file.arrayBuffer()), file.size, {
                                'Content-Type': file.type,
                                'Attachment-Expiry': Date.now() + getAttachmentExpiry(form.retention_type, form.retention_limit) * 1000
                            })
                            attachments.push({ name: key, key: attachment_id, filename: file.name })
                        } else {
                            console.warn(`Attachment exceeds ${Bun.env.ATTACHMENT_LIMIT || 20}MB`, key)
                        }
                    }
                } else {
                    fields.push({ name: key, value: Array.isArray(formData[key]) ? formData[key].join(', ') : formData[key] })
                }
            }
        }
        // add to mail queue
        hasher.update(JSON.stringify({ form_id, fields, attachments })) // calc sha256 of data for in-queue message deduplication
        const hex = hasher.digest("hex")
        const existing = await valkey.get(`streams:${hex}`)
        if(existing && !form.allow_duplicates) {
            if(Bun.env.DEBUG == "true") console.debug('Duplicate request', hex)
            return sendError(type, 409, 'Duplicate request', redirectFailUrl)
        } else {
            const stream_id = await valkey.xadd('messages', '*', 'hex', hex, 'form_id', form_id, 'fields', JSON.stringify(fields), 'origin', origin, 'attachment_count', attachments.length)
            if(!stream_id) {
                console.warn('Could not add message to queue', req)
                return sendError(type, 500, 'Could not add message to queue', redirectFailUrl)
            }
            if(existing) {
                await valkey.set(`streams:${hex}`, `${existing},${stream_id}`)
            } else {
                await valkey.set(`streams:${hex}`, stream_id)
                if(attachments.length) {
                    await valkey.hsetnx(`attachments:${hex}`, 'count', 0)
                    await valkey.hset(`attachments:${hex}`, 'form_id', form_id, 'files', JSON.stringify(attachments))
                    if(form!.retention_limit > 0 && form!.retention_type !== 'downloads') {
                        await valkey.expire(`attachments:${hex}`, getAttachmentExpiry(form.retention_type, form.retention_limit))
                    }
                }
            }
        }

        return type === 'form' ?
            sendRedirect(redirectSuccessUrl, 'true', 'success') :
            sendResponse('json', 200, {success: true})
    }
  },
  async fetch(req) {
    if (req.method === 'OPTIONS') {
      return new Response('Departed', {
        headers: cors
      })
    }
    return sendResponse(getRequestType(req) || 'form', 404, 'Route not found, please check the documentation at docs.email4.dev', true)
  }
})

const getAttachmentExpiry = (retention_type: string, retention_limit: number) => {
    let expiry = 0
    switch(retention_type) {
        case 'hours':
            expiry += retention_limit * 60
            break
        case 'days':
            expiry += retention_limit * 86400
            break
        case 'weeks':
            expiry += retention_limit * 86400 * 7
            break
        case 'months':
            expiry += retention_limit * 86400 * 30
            break
        default:
            expiry += 86400 // default 1 day
    }
    return expiry
}

const validateForm = async (form_id: string|null, origin: string) => {
    if(!form_id) {
        return {
            handler_id: '',
            error: {
                status: 400,
                message: 'Form parameter missing'
            }
        }
    }
    const form = await db.collection('forms').getOne(form_id).then(data => data).catch(() => null)
    if(form === null) {
        return {
            handler_id: '',
            error: {
                status: 404,
                message: 'Form missing'
            }
        }
    }
    if(!form.unprotected) {
        const domains = await db.collection('domains').getFullList().then(data => data).catch(() => [])
        const originDomain = getDomain(origin)
        if(!originDomain) {
            return {
                handler_id: '',
                error: {
                    status: 403,
                    message: 'Blocked server-side request'
                }
            }
        }
        const found = domains.find(d => d.name === originDomain)
        if(!found) {
            return {
                handler_id: '',
                error: {
                    status: 403,
                    message: 'Domain mismatch'
                }
            }
        }
        const last_update = new Date(found.updated.replace(' ', 'T'))
        const now = Date.now()
        if(!found.verified.includes('ownership') || now - last_update.getTime() > parseInt(Bun.env.VERIFICATION_EXPIRE || "24") * 60 * 60 * 1000) { // re-verify every now and then
            if(found.verified.includes('ownership')) {
                if(Bun.env.DEBUG == "true") console.debug(`Domain verification for ${found.name} has expired.`)
                await db.collection("domains").update(found.id, {
                    "verified-": 'ownership'
                })
            }
            hasher.update(`${found.id}_${found.created}`)
            if(Bun.env.DEBUG == "true") console.debug(`Domain verification for ${found.name} running...`)
            const verifyResult = await verifyDomain(found.name, hasher.digest("hex"))
            if(!verifyResult.status) {
                console.warn(`Domain verification failed for: ${found.name}`)
                return {
                    handler_id: '',
                    error: {
                        status: 403,
                        message: (Bun.env.DEBUG == "true") ? verifyResult.message : 'Domain not verified'
                    }
                }
            } else {
                await db.collection("domains").update(found.id, {
                    "verified+": 'ownership'
                })
            }
        }
    }
    return {
        handler_id: form.handler,
        error: null
    }
}