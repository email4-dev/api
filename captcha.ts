import { createChallenge, verifySolution } from 'altcha-lib'
import Valkey from 'iovalkey'
import type { Payload } from 'altcha-lib/types'

export const challenge = async (valkey: Valkey, receiver_id: string) => {
    const expires = new Date(Date.now() + (parseInt(Bun.env.CAPTCHA_EXPIRE!) || 60) * 1000)
    const result = await createChallenge({ hmacKey: receiver_id, number: parseInt(Bun.env.CAPTCHA_COMPLEXITY!) || 100_000, expires })
    try {
        await valkey.set(`ALTCHA_${result.challenge}`, receiver_id, "EX", parseInt(Bun.env.CAPTCHA_EXPIRE!) || 60)
    } catch(e: unknown) {
        if(Bun.env.DEBUG == "true") console.warn('The challenge key already exists', {key: result.challenge, receiver_id})
        return false
    }
    return result
}

export const verify = async (valkey: Valkey, payload: Payload, receiver_id: string) => {
    let result = false
    const value = await valkey.get(`ALTCHA_${payload.challenge}`)
    if(value === null) {
        if(Bun.env.DEBUG == "true")  console.warn('The challenge key doesn\'t exist, probably has expired', {payload, receiver_id})
    } else {
        if(value === receiver_id) {
            result = await verifySolution(payload, receiver_id)
        } else {
            if(Bun.env.DEBUG == "true")  console.warn('The challenge key already exists, but is assigned to another receiver', {payload, receiver_id})
        }
    }
    if(result) await valkey.del(`ALTCHA_${payload.challenge}`) // a challenge can only be used only once
    return result
}