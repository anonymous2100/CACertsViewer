package com.ctgu.model;

import java.nio.file.Path;
import java.time.Instant;

/**
 * @author lihuahui
 * @version 1.0
 * @description: 备份记录实体
 * @date 2026-04-10 14:00
 */
public record BackupRecord(Path backupPath, Path originalPath, Instant createdAt, long size)
{
}
