/**
 * This is a manual single-file merge of https://github.com/MajorTom327/spf-master
 * with a few fixes as it wouldn't build itself properly.
 * Since I'm using Bun I don't need a build step, TS runs natively
 * Check license at ./LICENSE-SPF-MASTER
**/ 

import * as dns from "dns"
import SpfParser from "spf-parse"
import ipRegex from 'ip-regex'
import {
  pathOr,
  or,
  propEq,
  prop,
  equals,
  propOr,
  flatten,
  path,
  defaultTo,
  compose,
  reject,
  either,
  isNil,
  isEmpty,
  length,
  curry,
} from "rambda"

const contains = curry((item: string, list: string[]) => list.includes(item))

declare enum InspecterError {
    UNKNWON = "EUNKNWON",
    NOTFOUND = "ENOTFOUND",
    IPS_NOT_MATCH = "IPSMATCH",
    INC_NOT_MATCH = "INCMATCH",
    DOM_NOT_MATCH = "DOMMATCH"
}

type Search = {
    ips: string[];
    includes: string[];
    domains: string[];
}

declare enum SpfType {
    include = "include",
    version = "version",
    all = "all",
    mx = "mx",
    ip4 = "ip4",
    ip6 = "ip6",
    a = "a"
}

interface SpfMechanism {
    prefix: string;
    type: SpfType;
    prefixdesc?: string;
    description: string;
    value: string;
}

interface SpfRecord {
    mechanisms: SpfMechanism[];
    valid: boolean;
}

interface Record {
    record: string;
    detail: SpfRecord;
    includes?: Record[];
}

export type Report = {
    records: Record[];
    found: {
        ips: string[];
        includes: string[];
        domains: string[];
    };
    isMatch: boolean;
    reason: string;
}

type Status = {
    found: boolean;
    match: boolean;
    lookups: number;
} & Search;

const isRawIp = (domain: string): boolean =>
ipRegex.v4().test(domain) || ipRegex.v6().test(domain);

const SpfInspector = (
domain: string,
search: Partial<Search> & { maxDepth?: number } = {},
stopOnMatch: boolean = true
): Promise<Report> => {
    let status: Status = {
        found: false,
        ips: [],
        includes: [],
        domains: [],
        match: false,
        lookups: 0,
    }

    const getDnsRecord = (domain: string): Promise<Record[]> => {
        if (isRawIp(domain))
        return Promise.reject(new Error(`Domain ${domain} is a raw ip !`))
        return new Promise<Record[]>((resolve, reject) => {
            dns.resolveTxt(domain, (err, entries) => {
                if (err) return reject(err)
                resolve(
                entries
                    .reduce((accumulator, currentValue) => [
                        ...accumulator,
                        ...currentValue,
                    ])
                    .filter((record: string): boolean => record.includes("v=spf1"))
                    .map(
                        (record: string): Record => ({
                            record,
                            detail: SpfParser(record || ""),
                        })
                    )
                )
            })
        })
    }

    const updateState = (record: Record): void => {
        const mechanisms = pathOr([], ["detail", "mechanisms"], record)

        if (length(mechanisms) === 0) return;

        mechanisms
        .filter(or(propEq(SpfType.ip4, "type"), propEq(SpfType.ip6, "type")))
        .map(prop("value"))
        .forEach((ip) => {
            if (contains(ip, status.ips)) return
            status.ips.push(ip)
        })

        mechanisms
        .filter(propEq(SpfType.include, "type"))
        .map(prop("value"))
        .forEach((include) => {
            status.lookups += 1
            if (contains(include, status.includes)) return
            status.includes.push(include)
        })

        mechanisms
        .filter(propEq(SpfType.a, "type"))
        .map(prop("value"))
        .forEach((domain) => {
            status.lookups += 1
            if (contains(domain, status.domains)) return
            status.domains.push(domain)
        })

        status.match =
        [
            equals(status.includes, propOr([], "includes", search)),
            equals(status.ips, propOr([], "ips", search)),
            equals(status.domains, propOr([], "domains", search)),
        ].every(equals(true)) || status.match
    }

    const getIncludes = async (record: Record, depth: number) => {
        updateState(record);

        if (status.match && stopOnMatch) return Promise.resolve(record)
        if (depth < 0) return Promise.resolve(record)

        // * Get next includes to parse
        const includes: SpfMechanism[] = pathOr(
            [],
            ["detail", "mechanisms"],
            record
        ).filter(propEq(SpfType.include, "type"))

        // * We are a the lowest level
        if (length(includes) === 0) return Promise.resolve(record)

        const recordsFromIncludes: Record[][] = await Promise.all(
            includes
                .map((include: SpfMechanism): string => include.value) // * Map values
                .map((include: string): Promise<Record[]> => getDnsRecord(include)) // * Get the record
        )

        // * Recursion call to get sub-includes
        record.includes = await Promise.all(
            flatten(recordsFromIncludes).map(
                // @ts-expect-error
                (el: Record) =>
                new Promise<Record>(async (resolve) =>
                    resolve(await getIncludes(el, depth - 1))
                )
            )
        )
        return Promise.resolve(record)
    }

    return getDnsRecord(domain).then((records) => {
        return Promise.all(
            records.map((record: Record): Promise<Record> => {
                if (path(["detail", "valid"], record))
                return getIncludes(
                    record,
                    Math.max(0, defaultTo(10, search.maxDepth))
                )
                return Promise.resolve(record)
            })
        )
        .then((records: Record[]) => {
            const helperRemoveEmpty = compose(
                reject(either(isNil, isEmpty)),
                defaultTo([])
            )
            return Promise.resolve({
                records: records || [],
                found: {
                    // @ts-expect-error
                    ips: helperRemoveEmpty(status.ips),
                    // @ts-expect-error
                    includes: helperRemoveEmpty(status.includes),
                    // @ts-expect-error
                    domains: helperRemoveEmpty(status.domains),
                },
                isMatch: status.match,
                lookups: status.lookups,
                reason: "",
            })
        })
        .catch((err) => {
            return Promise.reject({
                records: [],
                found: {
                    ips: [],
                    includes: [],
                    domains: [],
                },
                isMatch: false,
                lookups: 0,
                reason: InspecterError.NOTFOUND,
            })
        })
    })
}

export default SpfInspector