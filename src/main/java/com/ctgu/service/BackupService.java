package com.ctgu.service;

import com.ctgu.model.BackupRecord;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;

/**
 * @author lihuahui
 * @version 1.0
 * @description: 备份服务类，负责创建、列出和恢复备份
 * @date 2026-04-10 14:00
 */
public class BackupService
{
  private static final DateTimeFormatter TIMESTAMP_FORMAT =
      DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss", Locale.ROOT).withZone(ZoneOffset.UTC);

  public Path backupDirectoryFor(Path storePath)
  {
    String safeName = storePath.getFileName().toString().replaceAll("[^a-zA-Z0-9._-]", "_");
    return storePath.getParent().resolve(".cacertsviewer-backups").resolve(safeName);
  }

  public BackupRecord createBackup(Path storePath) throws IOException
  {
    Path backupDirectory = backupDirectoryFor(storePath);
    Files.createDirectories(backupDirectory);
    String backupFileName = TIMESTAMP_FORMAT.format(Instant.now()) + "-" + storePath.getFileName();
    Path backupPath = backupDirectory.resolve(backupFileName);
    Files.copy(storePath, backupPath, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.COPY_ATTRIBUTES);
    return new BackupRecord(backupPath, storePath, Files.getLastModifiedTime(backupPath).toInstant(), Files.size(backupPath));
  }

  public List<BackupRecord> listBackups(Path storePath) throws IOException
  {
    Path backupDirectory = backupDirectoryFor(storePath);
    if(!Files.exists(backupDirectory))
    {
      return List.of();
    }

    try (Stream<Path> stream = Files.list(backupDirectory))
    {
      return stream.filter(Files::isRegularFile).map(path -> toRecord(path, storePath))
          .sorted(Comparator.comparing(BackupRecord::createdAt).reversed()).toList();
    }
  }

  public void restoreBackup(BackupRecord backupRecord) throws IOException
  {
    Files.copy(backupRecord.backupPath(), backupRecord.originalPath(), StandardCopyOption.REPLACE_EXISTING,
        StandardCopyOption.COPY_ATTRIBUTES);
  }

  private BackupRecord toRecord(Path backupPath, Path originalPath)
  {
    try
    {
      return new BackupRecord(backupPath, originalPath, Files.getLastModifiedTime(backupPath).toInstant(), Files.size(backupPath));
    }
    catch(IOException ex)
    {
      return new BackupRecord(backupPath, originalPath, Instant.EPOCH, -1);
    }
  }
}
