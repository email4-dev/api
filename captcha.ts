import { createChallenge, verifySolution } from 'altcha-lib'
import { type KV, Kvm } from "@nats-io/kv"
import { Payload } from 'altcha-lib/types'

let bucket: KV

export const alcthaInit = async (kvm: Kvm) => {
    try {
        bucket = await kvm.open('altcha')
        const bucketStatus = await bucket.status()
        if(bucketStatus.ttl != parseInt(Bun.env.CAPTCHA_EXPIRE!) * 1000) {
            console.warn('CAPTCHA_EXPIRE has changed, recreating bucket...')
            bucket.destroy()
            kvm.create('altcha', {
                ttl: parseInt(Bun.env.CAPTCHA_EXPIRE!) * 1000
            })
        }
    } catch (e: unknown) {
        console.warn('Captcha bucket doesn\'t exist, creating bucket...')
        kvm.create('altcha', {
            ttl: parseInt(Bun.env.CAPTCHA_EXPIRE!) * 1000
        })
    }
}

export const challenge = async (receiver_id: string) => {
    const expires = new Date(Date.now() + parseInt(Bun.env.CAPTCHA_EXPIRE!) * 1000)
    const result = await createChallenge({ hmacKey: receiver_id, number: parseInt(Bun.env.CAPTCHA_COMPLEXITY!), expires })
    try {
        await bucket.create(result.challenge, receiver_id)
    } catch(e: unknown) {
        if(Bun.env.DEBUG == "true") console.warn('The challenge key already exists', {key: result.challenge, receiver_id})
        return false
    }
    return result
}

export const verify = async (payload: Payload, receiver_id: string) => {
    let result = false
    const value = await bucket.get(payload.challenge)
    if(value === null) {
        if(Bun.env.DEBUG == "true")  console.warn('The challenge key doesn\'t exist, probably has expired', {payload, receiver_id})
    } else {
        if(value.string() === receiver_id) {
            result = await verifySolution(payload, receiver_id)
        } else {
            if(Bun.env.DEBUG == "true")  console.warn('The challenge key already exists, but is assigned to another receiver', {payload, receiver_id})
        }
    }
    if(result) await bucket.delete(payload.challenge) // a challenge must be used only once
    return result
}