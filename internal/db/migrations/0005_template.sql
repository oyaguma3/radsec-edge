-- テナントのコンテナのひな形の記録（設計概要 §24.14 の U6-1）。template はひな形の版（0 はまだ記録していない）、
-- image_id は radsecproxy のイメージの ID。prev_* は 1 つ前の形（前の形に戻すときに使う。なければ 0 と空）。
-- 段階 6 より前に作ったコンテナは、最初の整合ループでそのコンテナの形を記録する（作り直さない）。
ALTER TABLE tenants ADD COLUMN template INTEGER NOT NULL DEFAULT 0;
ALTER TABLE tenants ADD COLUMN image_id TEXT NOT NULL DEFAULT '';
ALTER TABLE tenants ADD COLUMN prev_template INTEGER NOT NULL DEFAULT 0;
ALTER TABLE tenants ADD COLUMN prev_image_id TEXT NOT NULL DEFAULT '';
