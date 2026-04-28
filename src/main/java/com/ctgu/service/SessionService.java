package com.ctgu.service;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.prefs.Preferences;

/**
 * @author lihuahui
 * @version 1.0
 * @description: 会话服务，负责保存和加载用户会话相关的数据，如打开的文件列表和密码等
 * @date 2026-04-10 14:05
 */
public class SessionService
{
  private static final String PREF_OPEN_FILES = "session_open_files";
  private static final String PREF_PWD_PREFIX = "pwd_";

  private final Preferences prefs;

  public SessionService()
  {
    prefs = Preferences.userNodeForPackage(SessionService.class);
  }

  /* ---- Open-file list ---- */

  public void saveOpenFiles(List<Path> paths)
  {
    StringJoiner joiner = new StringJoiner("\n");
    for(Path p : paths)
    {
      joiner.add(p.toAbsolutePath().toString());
    }
    prefs.put(PREF_OPEN_FILES, joiner.toString());
  }

  public List<Path> loadOpenFiles()
  {
    String raw = prefs.get(PREF_OPEN_FILES, "");
    if(raw.isBlank())
    {
      return List.of();
    }
    List<Path> result = new ArrayList<>();
    for(String line : raw.split("\n"))
    {
      String trimmed = line.trim();
      if(!trimmed.isEmpty())
      {
        Path p = Path.of(trimmed);
        if(Files.exists(p))
        {
          result.add(p);
        }
      }
    }
    return result;
  }

  /* ---- Password store ---- */

  public void savePassword(Path path, char[] password)
  {
    if(path == null || password == null)
    {
      return;
    }
    String key = passwordKey(path);
    String encoded = Base64.getEncoder().encodeToString(new String(password).getBytes(StandardCharsets.UTF_8));
    prefs.put(key, encoded);
  }

  public Optional<char[]> loadPassword(Path path)
  {
    if(path == null)
    {
      return Optional.empty();
    }
    String key = passwordKey(path);
    String encoded = prefs.get(key, null);
    if(encoded == null || encoded.isBlank())
    {
      return Optional.empty();
    }
    try
    {
      byte[] decoded = Base64.getDecoder().decode(encoded);
      return Optional.of(new String(decoded, StandardCharsets.UTF_8).toCharArray());
    }
    catch(IllegalArgumentException ex)
    {
      return Optional.empty();
    }
  }

  public void removePassword(Path path)
  {
    if(path != null)
    {
      prefs.remove(passwordKey(path));
    }
  }

  private String passwordKey(Path path)
  {
    // Hash the absolute path to produce a safe, fixed-length Preferences key
    return PREF_PWD_PREFIX + Integer.toHexString(path.toAbsolutePath().toString().hashCode());
  }
}

