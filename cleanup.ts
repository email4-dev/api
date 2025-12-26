import * as Minio from 'minio'

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

const stream = minio.listObjectsV2(bucket, '', true)
const expired: string[] = []
const now = Date.now()
stream.on('data', async function (obj) {
  const stats = await minio.statObject(bucket, obj.name!)
  if(parseInt(stats.metaData['Attachment-Expiry']) < now) expired.push(obj.name!)
})
stream.on('end', async function () {
  await minio.removeObjects(bucket, expired)
})
stream.on('error', function (err) {
  console.error('Cleanup failed:', err)
})