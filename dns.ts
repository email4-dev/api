import { getDnsRecords } from '@layered/dns-records'

export const verifyDomain = async (domain: string, verification: string) => {
    let result = {
        status: false,
        message: ''
    }
    const records = await getDnsRecords(domain, 'TXT')
    const verRecord = records.filter(record => record.data.includes('email4.dev-verification='))
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