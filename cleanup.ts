import * as Minio from 'minio'

const minio = new Minio.Client({
  endPoint: 'minio',
  port: 9000,
  accessKey: Bun.env.MINIO_ROOT_USER!,
  secretKey: Bun.env.MINIO_ROOT_PASSWORD!,
  useSSL: false,
  pathStyle: true
})

const stream = minio.listObjectsV2('attachments', '', true)
const expired: string[] = []
const now = Date.now()
stream.on('data', async function (obj) {
  const stats = await minio.statObject('attachments', obj.name!)
  if(parseInt(stats.metaData['Attachment-Expiry']) < now) expired.push(obj.name!)
})
stream.on('end', async function () {
  await minio.removeObjects('attachments', expired)
})
stream.on('error', function (err) {
  console.error('Cleanup failed:', err)
})