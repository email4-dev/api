import { alcthaInit, challenge, verify } from './captcha'
import { getDomain } from 'tldjs'
import { connect, headers } from "@nats-io/transport-node"
import { jetstreamManager, RetentionPolicy, StorageType } from "@nats-io/jetstream"
import { Objm } from "@nats-io/obj"
import crypto from 'crypto'
import PocketBase from 'pocketbase'
import { Kvm } from '@nats-io/kv'
import { verifyDomain } from './dns'
import { serve } from 'bun'

const db = new PocketBase(Bun.env.POCKETBASE_URL)

console.log('Email4.dev API starting...')

await db.collection('_superusers').authWithPassword(
    Bun.env.POCKETBASE_EMAIL!,
    Bun.env.POCKETBASE_PASS!,
)

if(!db.authStore.isValid) {
    console.error('Pocketbase authentication failed!')
    process.exit(1)
}

const nc = await connect({ servers: Bun.env.NATS_HOST })
const js = await jetstreamManager(nc)
const objm = new Objm(nc)
const hasher = new Bun.CryptoHasher("sha256")
const bucket = await objm.create("attachments", { storage: StorageType.File })

nc.closed().then((err) => {
    if(err) {
        console.error('NATS disconnected', err.message)
    } else {
        console.error('NATS disconnected')
    }
    process.exit(1)
})

process.on("beforeExit", async () => {
    console.log('Email4.dev API exiting gracefully...')
    await nc.close()
    db.authStore.clear()
})

try {
    const streamInfo = await js.streams.info("messages")
} catch (err: any) {
    console.warn('Messages stream not found, creating it...')
    await js.streams.add({
        name: "messages",
        subjects: [`message.>`],
        retention: RetentionPolicy.Workqueue
    })
}

try {
    const kvm = new Kvm(js.jetstream())
    await alcthaInit(kvm)
} catch (e: unknown) {
    console.error('Cannot initiate NATS K/V store connection.', (e as Error).message)
    process.exit(1)
}

const cors = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST',
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
    return Response.redirect(`${url}&${key}=${encodeURIComponent(message)}`, 303)
}

const sendError = (type: string, status: number, message: string, redirect: string | null = null) => {
    if(redirect !== null && type !== 'json') {
        return sendRedirect(redirect, message, 'error')
    } else {
        return sendResponse(type, status, message, true)
    }
}

serve({
  port: 3000,
  async fetch(req) {
    // CORS
    if (req.method === 'OPTIONS') {
      return new Response(null, {
        headers: cors
      })
    }
    // Get request data
    let type: null | 'json' | 'form' = null
    switch(req.headers.get('content-type')) {
        case 'application/json':
            type = 'json'
            break
        case 'application/x-www-form-urlencoded':
        case 'multipart/form-data':
            type = 'form'
            break
    }
    const origin = req.headers.get('origin') || ''
    // Routing
    const url = new URL(req.url)
    const [ _, action, form_id] = url.pathname.split('/')
    switch(action) {
        case 'altcha': {
            if(req.method !== "GET") {
                return sendError('json', 405, 'HTTP method not supported')
            }
            if(Bun.env.DEBUG == "true") console.debug('Altcha init', req)
            let { handler_id, error } = await validateForm(form_id, origin)
            if(error) {
                console.warn('Altcha error', form_id, error?.message)
                return sendError('json', error?.status, error.message)
            }
            const now = new Date()
            const hmac = await challenge(handler_id)
            return Response.json(hmac, { headers: {
                ...cors,
                Expires: new Date(now.getTime() + (parseInt(Bun.env.CAPTCHA_EXPIRE!) * 1000)).toUTCString()
            }})
        }
        case 'submit': {
            if(type === null) {
                return sendError('form', 405, 'HTTP method not supported')
            }
            if(Bun.env.DEBUG == "true") console.debug('Form submission', req)
            const formData = type === 'form' ? await req.formData() : await req.json()
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
            // @ts-expect-error
            const redirectFail: Boolean = form.expand?.handler.expand?.domains.some(d => d.name == getDomain(form.expand?.handler.redirect_fail) && d.verified.includes('ownership'))
            // @ts-expect-error
            const redirectSuccess: Boolean = form.expand?.handler.expand?.domains.some(d => d.name == getDomain(form.expand?.handler.redirect_success) && d.verified.includes('ownership'))
            // check altcha
            if(form.expand?.handler.altcha) {
                const altchaData = type === 'form' ? formData.get('altcha') : formData.altcha
                if(!altchaData) {
                    console.warn('Altcha field missing in form:', form_id)
                    return sendError(type, 403, 'Altcha field missing', redirectFail ? form.expand?.handler.redirect_fail : null)
                } else {
                    const payload = JSON.parse(atob(altchaData))
                    const altchaResult = await verify(payload, form.handler)
                    if(!altchaResult) {
                        console.warn('Altcha mismatch for form:', form_id)
                        return sendError(type, 403, 'Altcha mismatch', redirectFail ? form.expand?.handler.redirect_fail : null)
                    }
                }
            }
            // check honeypot
            if(form.expand?.handler.honeypot.length) {
                const honeypotData = type === 'form' ? formData.get(form.expand?.handler.honeypot) : formData[form.expand?.handler.honeypot]
                if(!honeypotData) {
                    console.warn('Honeypot enabled but not implemented', req)
                    return sendError(type, 400, 'Honeypot missing', redirectFail ? form.expand?.handler.redirect_fail : null)
                } else {
                    if(honeypotData.length) {
                        console.info('Bot detected!', req)
                        return sendError(type, 403, 'Bot detected')
                    }
                }
            }
            // init data variables
            const fields:{[x: string]: any}[] = []
            const attachments:{name: string, key: string, filename: string}[] = []
            // loop fields
            if(type === 'form') {
                for (const key of formData.keys()) {
                    if(key === 'altcha') continue
                    if(form.expand?.handler.honeypot.length && key === form.expand?.handler.honeypot) continue
                    const values: string[]|File[] = formData.getAll(key)
                    if(values[0] instanceof File) {
                        for(let i=0;i<values.length;i++) {
                            const file = values[i] as File
                            // 20mb default limit
                            if(file.size < (parseInt(Bun.env.ATTACHMENT_LIMIT || "20") * 1024 * 1024)) {
                                const attachment_id = crypto.randomUUID()
                                await bucket.put({ name: attachment_id }, readableStreamFrom(await file.bytes()))
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
                for (const key of Object.keys(formData)) {
                    if(key === 'altcha') continue
                    if(form.expand?.handler.honeypot.length && key === form.expand?.handler.honeypot) continue
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
                                await bucket.put({ name: attachment_id }, readableStreamFrom(await file.bytes()))
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
            // add to NATS queue
            const data = JSON.stringify({ form_id, fields, attachments })
            const msgHeaders = headers()
            hasher.update(data) // calc sha256 of data for in-queue message deduplication, a.k.a. duplicate requests won't be added to the queue
            msgHeaders.set('Nats-Msg-Id', hasher.digest("hex"))
            nc.publish(`message.${form_id}`, data, { headers: msgHeaders })

            return type === 'form' ?
                sendRedirect(redirectSuccess ? form.expand?.handler.redirect_success : req.headers.get("referer"), 'true', 'success') :
                sendResponse('json', 200, {success: true})
        }
    }
    // 404 fallback
    return sendResponse(type || 'form', 404, 'Route not found, please check the documentation at docs.email4.dev', true)
  }
})

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
                if(Bun.env.DEBUG == "true") console.log(`Domain verification for ${found.name} has expired.`)
                await db.collection("domains").update(found.id, {
                    "verified-": 'ownership'
                })
            }
            hasher.update(`${found.id}_${found.created}`)
            if(Bun.env.DEBUG == "true") console.log(`Domain verification for ${found.name} running...`)
            const verifyResult = await verifyDomain(found.name, hasher.digest("hex"))
            if(!verifyResult.status) {
                console.warn(`Domain verification failed for: ${found.name}`)
                return {
                    handler_id: '',
                    error: {
                        status: 403,
                        message: 'Domain not verified'
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

function readableStreamFrom(data: Uint8Array): ReadableStream<Uint8Array> {
    return new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.enqueue(data)
        controller.close()
      },
    })
}