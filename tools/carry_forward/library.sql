-- A small synthetic library for the carry-forward proof, loaded into a schema the product's own
-- migrations created. Every value is generated; nothing here came from a real library.
\set ON_ERROR_STOP 1
BEGIN;
SET LOCAL synchronous_commit = off;

CREATE TEMP TABLE carry_user AS
  SELECT uuid_generate_v4() AS id, uuid_generate_v4() AS cluster, g AS n FROM generate_series(1, 3) g;
INSERT INTO cluster_group (id) SELECT cluster FROM carry_user;
INSERT INTO "user" (id, email, name, "isAdmin", "clusterGroupId")
  SELECT id, 'person' || n || '@example.test', 'Synthetic Person ' || n, n = 1, cluster FROM carry_user;

CREATE TEMP TABLE carry_asset AS
  SELECT uuid_generate_v4() AS id, g AS n, (SELECT id FROM carry_user WHERE n = 1 + g % 3) AS owner,
         timestamptz '2012-01-01 08:00:00+00' + (g * interval '11 hours 7 minutes') AS taken
  FROM generate_series(1, 6000) g;
INSERT INTO asset (id, "ownerId", type, "originalPath", "fileCreatedAt", "fileModifiedAt", checksum, "checksumAlgorithm",
                   "originalFileName", "localDateTime", "isFavorite", width, height)
  SELECT id, owner, CASE WHEN n % 10 = 0 THEN 'VIDEO' ELSE 'IMAGE' END,
         '/library/' || owner || '/' || to_char(taken, 'YYYY/MM') || '/IMG_' || lpad(n::text, 5, '0') || CASE WHEN n % 10 = 0 THEN '.mov' ELSE '.heic' END,
         taken, taken, decode(md5(n::text) || md5('c' || n), 'hex'),
         (SELECT enumlabel FROM pg_enum WHERE enumtypid = 'asset_checksum_algorithm_enum'::regtype ORDER BY enumsortorder LIMIT 1)::asset_checksum_algorithm_enum,
         'IMG_' || lpad(n::text, 5, '0') || CASE WHEN n % 10 = 0 THEN '.mov' ELSE '.heic' END, taken, n % 17 = 0,
         4032, 3024
  FROM carry_asset;
INSERT INTO asset_exif ("assetId", make, model, "exifImageWidth", "exifImageHeight", "fileSizeInByte", "dateTimeOriginal", "lensModel",
                        "fNumber", "focalLength", iso, latitude, longitude, city, state, country, description, "timeZone")
  SELECT id, (ARRAY['Apple', 'Canon', 'Fujifilm', 'Sony'])[1 + n % 4], 'Model ' || (n % 9), 4032, 3024, 1500000 + (n * 7919) % 9000000, taken,
         'Lens ' || (n % 5), 1.8 + (n % 6) * 0.4, 24 + (n % 5) * 11, 50 * (1 + n % 16), 35 + (n % 2000) / 100.0, -120 + (n % 9000) / 100.0,
         'City ' || (n % 40), 'Region ' || (n % 12), 'Country ' || (n % 5), CASE WHEN n % 7 = 0 THEN 'Synthetic caption ' || n ELSE '' END, 'UTC'
  FROM carry_asset;
INSERT INTO asset_file ("assetId", type, path)
  SELECT id, kind, '/library/thumbs/' || id || '/' || kind || '.webp' FROM carry_asset, unnest(ARRAY['thumbnail', 'preview']) kind;

-- One embedding per photo and per face, each a fresh random direction of the column's own dimension.
DO $$
DECLARE clip int := (SELECT atttypmod FROM pg_attribute WHERE attrelid = 'smart_search'::regclass AND attname = 'embedding');
        face int := (SELECT atttypmod FROM pg_attribute WHERE attrelid = 'face_search'::regclass AND attname = 'embedding');
BEGIN
  CREATE TEMP TABLE carry_dimensions AS SELECT clip AS clip, face AS face;
END $$;
INSERT INTO smart_search ("assetId", embedding)
  SELECT a.id, (SELECT array_agg(random() - 0.5) FROM generate_series(1, (SELECT clip FROM carry_dimensions)) WHERE a.n IS NOT NULL)::vector FROM carry_asset a;

CREATE TEMP TABLE carry_person AS
  SELECT uuid_generate_v4() AS grp, g AS n, (SELECT id FROM carry_user WHERE n = 1 + g % 3) AS owner FROM generate_series(1, 40) g;
INSERT INTO person_group (id, "clusterGroupId") SELECT p.grp, u.cluster FROM carry_person p JOIN carry_user u ON u.id = p.owner;
INSERT INTO person ("ownerId", "personGroupId", name) SELECT owner, grp, 'Synthetic Face ' || n FROM carry_person;
CREATE TEMP TABLE carry_face AS
  SELECT uuid_generate_v4() AS id, a.id AS asset, a.n, (SELECT grp FROM carry_person WHERE n = 1 + a.n % 40) AS grp
  FROM carry_asset a WHERE a.n % 3 <> 0;
INSERT INTO asset_face (id, "assetId", "personGroupId", "imageWidth", "imageHeight", "boundingBoxX1", "boundingBoxY1", "boundingBoxX2", "boundingBoxY2")
  SELECT id, asset, grp, 4032, 3024, 100 + n % 900, 100 + n % 700, 1200 + n % 900, 1300 + n % 700 FROM carry_face;
INSERT INTO face_search ("faceId", embedding)
  SELECT f.id, (SELECT array_agg(random() - 0.5) FROM generate_series(1, (SELECT face FROM carry_dimensions)) WHERE f.n IS NOT NULL)::vector FROM carry_face f;

CREATE TEMP TABLE carry_album AS
  SELECT uuid_generate_v4() AS id, g AS n, (SELECT id FROM carry_user WHERE n = 1 + g % 3) AS owner FROM generate_series(1, 60) g;
INSERT INTO album (id, "albumName", description) SELECT id, 'Synthetic album ' || n, 'Generated for the carry-forward proof' FROM carry_album;
INSERT INTO album_user ("albumId", "userId", role)
  SELECT id, owner, (SELECT enumlabel FROM pg_enum WHERE enumtypid = 'album_user_role_enum'::regtype ORDER BY enumsortorder LIMIT 1)::album_user_role_enum FROM carry_album;
INSERT INTO album_asset ("albumId", "assetId")
  SELECT b.id, a.id FROM carry_album b JOIN carry_asset a ON a.n % 60 = b.n % 60 OR (a.n + 7) % 60 = b.n % 60;
INSERT INTO activity ("albumId", "userId", "assetId", comment, "isLiked")
  SELECT b.id, b.owner, a.id, CASE WHEN a.n % 2 = 0 THEN 'Synthetic comment ' || a.n END, a.n % 2 <> 0
  FROM carry_album b JOIN carry_asset a ON a.n % 60 = b.n % 60 WHERE a.n <= 240;

CREATE TEMP TABLE carry_tag AS
  SELECT uuid_generate_v4() AS id, g AS n, (SELECT id FROM carry_user WHERE n = 1) AS owner FROM generate_series(1, 30) g;
INSERT INTO tag (id, "userId", value) SELECT id, owner, 'synthetic/tag-' || n FROM carry_tag;
INSERT INTO tag_asset ("assetId", "tagId")
  SELECT a.id, t.id FROM carry_asset a JOIN carry_tag t ON t.n = 1 + a.n % 30 WHERE a.owner = t.owner;

CREATE TEMP TABLE carry_memory AS
  SELECT uuid_generate_v4() AS id, g AS n, (SELECT id FROM carry_user WHERE n = 1 + g % 3) AS owner FROM generate_series(1, 50) g;
INSERT INTO memory (id, "ownerId", type, data, "memoryAt")
  SELECT id, owner, 'on_this_day', jsonb_build_object('year', 2012 + n % 12), timestamptz '2024-01-01+00' + n * interval '1 day' FROM carry_memory;
INSERT INTO memory_asset ("memoriesId", "assetId")
  SELECT m.id, a.id FROM carry_memory m JOIN carry_asset a ON a.owner = m.owner AND a.n % 50 = m.n % 50 AND a.n <= 1500;
COMMIT;
ANALYZE;
