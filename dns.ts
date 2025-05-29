import { getDnsRecords } from '@layered/dns-records'
import { isValid } from 'tldjs' // unfortunately `isValidHostname()` isn't exported properly, I'll stick with the old method
import PocketBase from 'pocketbase'
import SpfInspector from './spf-master'

export const verifyDomain = async (domain: string, verification: string) => {
    let result = {
        status: false,
        message: ''
    }
    const records = await getDnsRecords(domain, 'TXT')
    const verRecord = records.filter(record => record.data.includes('mail4.dev-verification='))
    switch(verRecord.length) {
        case 0:
            result.message = 'TXT verification record missing'
            break
        case 1:
            result.status = verRecord[0].data.replaceAll('"', '').split('=')[1] === verification
            if(!result.status) result.message = 'TXT verification record is invalid'
            break
        default:
            verRecord.forEach(r => {
                if(r.data.replaceAll('"', '').split('=')[1] === verification) result.status = true
            })
            result.message = 'Multiple TXT verification records found'
            if(!result.status) result.message += '<br>TXT verification records are all invalid'
    }
    return result
}


export const verifySpfDkim = async (db: PocketBase, domain: string) => {
    const result = {
        spf: {
            status: false,
            reason: ''
        },
        dkim: {
            status: false,
            reason: ''
        }
    }
    const handlers = await db.collection('handlers').getFullList({
        filter: `domain = '${domain}'`,
        expand: 'gateway',
        fields: 'id,expand.gateway.hostname,expand.gateway.provider'
    }).then(data => data).catch(() => [])
    const spfQuery:{ips:Set<string>, domains:Set<string>, includes:Set<string>} = {
        ips: new Set<string>(),
        domains: new Set<string>(),
        includes: new Set<string>()
    }
    // verified => 0: doesn't exist, 1: exists with wrong value, 2: pass
    const dkimRecords:{id: string, type: string, record: string, value: string, verified: 0|1|2}[] = [
        {
            id: 'dkim-email',
            type: 'dkim_txt',
            record: 'email',
            value: '',
            verified: 0
        },
        {
            id: 'dkim-mail',
            type: 'dkim_txt',
            record: 'mail',
            value: '',
            verified: 0
        },
        {
            id: 'dkim-dkim',
            type: 'dkim_txt',
            record: 'dkim',
            value: '',
            verified: 0
        },
        {
            id: 'dkim-default',
            type: 'dkim_txt',
            record: 'default',
            value: '',
            verified: 0
        }
    ]
    handlers.some(async h => {
        const hostname = h.expand!.gateway.hostname
        if(!hostname) return true
        if(isValid(hostname)) {
            if(h.expand!.gateway.provider) {
                const spfRecords = await db.collection("provider_records").getFullList({
                    filter: `provider = '${h.expand!.gateway.provider}'`
                }).then(data => data).catch(() => [])
                if(spfRecords.length){
                    spfRecords.forEach(s => {
                        if(s.type === "spf") {
                            spfQuery.includes.add(s.record)
                        } else {
                            if(dkimRecords.findIndex(d => d.id === s.id) > -1) {
                                dkimRecords.push({
                                    id: s.id,
                                    type: s.type,
                                    record: s.record,
                                    value: s.value,
                                    verified: 0
                                })
                            }
                        }
                    })
                }
            } else {
                spfQuery.domains.add(hostname)
            }
        } else {
            spfQuery.ips.add(hostname)
        }
    })
    if(spfQuery.ips.size || spfQuery.domains.size || spfQuery.includes.size) {
        const spfQueryArray = {
            ips: Array.from(spfQuery.ips),
            domains: Array.from(spfQuery.domains),
            includes: Array.from(spfQuery.includes),
        }
        // {records: [], found: query, isMatch: false, reason: ""}
        const spfResult = await SpfInspector(domain, spfQueryArray, true)
        result.spf.status = spfResult.isMatch
        result.spf.reason = spfResult.reason
    } else {
        result.spf.reason = "No gateway hostnames found via associated handlers"
    }
    dkimRecords.forEach(async d => {
        if(d.record.indexOf('*') === -1) { // can't search wildcards
            const records = await getDnsRecords(`${d.record}._domainkey.${domain}`, d.type === 'dkim_txt' ? 'TXT' : 'CNAME')
            if(records.length) d.verified = 1
            for(let i=0; i<records.length; i++) {
                if(d.value){
                    if(records[i].data === d.value) {
                        d.verified = 2
                    } else {
                        result.dkim.reason += `${records[i].data} doesn't match suggested ${d.value}`
                    }
                }
            }
        }
    })
    return result
}