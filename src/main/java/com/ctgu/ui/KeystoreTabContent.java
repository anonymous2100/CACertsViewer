package com.ctgu.ui;

import com.ctgu.model.*;
import com.ctgu.service.*;
import com.ctgu.util.CertificateFormatter;
import com.ctgu.util.FingerprintUtils;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.DefaultTreeModel;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.*;
import java.util.List;

/**
 * @author lihuahui
 * @version 1.0
 * @description: KeystoreTabContent 代表主界面中每个标签页的内容和状态，负责渲染证书列表、详情和信任链，并处理与用户交互相关的业务逻辑
 * @date 2026-04-10 14:03
 */
public class KeystoreTabContent
{
  private static final int CHAIN_ROW_HEIGHT = 78;
  private static final int CHAIN_PANEL_MIN_HEIGHT = 110;
  private static final int CHAIN_PANEL_MAX_HEIGHT = 260;

  private final PropertyChangeSupport pcs = new PropertyChangeSupport(this);

  private final JFrame owner;
  private final TrustStoreService trustStoreService;
  private final BackupService backupService;
  private final ChainAnalysisService chainAnalysisService;
  private final SessionService sessionService;

  private final JPanel root = new JPanel(new BorderLayout());
  private final CertificateTableModel tableModel = new CertificateTableModel();
  private final JTable table = new JTable(tableModel);
  private final JTextField searchField = new JTextField();
  private final JTextArea detailsArea = new JTextArea();
  private final JTree chainTree = new JTree((javax.swing.tree.TreeModel)null);
  private final JScrollPane chainTreeScroll = new JScrollPane(chainTree);
  private final JLabel chainSummaryLabel = new JLabel("选择一个证书以查看其信任链。");
  private final JLabel bannerLabel = new JLabel();
  private final JButton copyButton = new JButton("复制详情");
  private final JButton detailExportButton = new JButton("导出证书");
  private final JButton exportPublicKeyButton = new JButton("导出公钥");
  private final JButton exportPrivateKeyButton = new JButton("导出私钥");
  private TrustStoreDocument document;
  private final java.beans.PropertyChangeListener docCertificatesListener = evt -> {
    if("certificates".equals(evt.getPropertyName()))
    {
      tableModel.refresh();
      updateBanner();
    }
  };
  private CertificateRecord selectedRecord;
  private String statusText = "";
  private String tabTitle = "新标签页";
  private final java.beans.PropertyChangeListener docDirtyListener = evt -> {
    if("dirty".equals(evt.getPropertyName()))
    {
      refreshChrome();
      pcs.firePropertyChange("dirty", evt.getOldValue(), evt.getNewValue());
    }
  };
  private TableRowSorter<CertificateTableModel> rowSorter;

  public KeystoreTabContent(JFrame owner, TrustStoreService trustStoreService, BackupService backupService,
      ChainAnalysisService chainAnalysisService, SessionService sessionService)
  {
    this.owner = owner;
    this.trustStoreService = trustStoreService;
    this.backupService = backupService;
    this.chainAnalysisService = chainAnalysisService;
    this.sessionService = sessionService;
    buildUi();
    bindState();
    root.putClientProperty("keystoreTabContent", this);
  }

  /* ---- Public API ---- */

  static boolean isStoreFile(Path path)
  {
    String fn = path.getFileName().toString().toLowerCase(Locale.ROOT);
    return fn.endsWith(".jks") || fn.endsWith(".p12") || fn.endsWith(".pkcs12") || fn.endsWith(".cacerts") || fn.equals("cacerts");
  }

  static boolean isCertificateFile(Path path)
  {
    String fn = path.getFileName().toString().toLowerCase(Locale.ROOT);
    return fn.endsWith(".cer") || fn.endsWith(".crt") || fn.endsWith(".pem") || fn.endsWith(".der");
  }

  public JComponent getContent()
  {
    return root;
  }

  public TrustStoreDocument getDocument()
  {
    return document;
  }

  private void setDocument(TrustStoreDocument newDoc)
  {
    TrustStoreDocument oldDoc = this.document;
    if(oldDoc != null)
    {
      oldDoc.removePropertyChangeListener("dirty", docDirtyListener);
      oldDoc.removePropertyChangeListener("certificates", docCertificatesListener);
    }
    this.document = newDoc;
    table.clearSelection();
    if(newDoc == null)
    {
      tableModel.setData(null);
      detailsArea.setText("");
      clearChainView();
      bannerLabel.setVisible(false);
      searchField.setText("");
    }
    else
    {
      newDoc.addPropertyChangeListener("dirty", docDirtyListener);
      newDoc.addPropertyChangeListener("certificates", docCertificatesListener);
      tableModel.setData(newDoc.getCertificates());
      updateFilter();
      updateBanner();
    }
    refreshChrome();
    pcs.firePropertyChange("document", oldDoc, newDoc);
  }

  public boolean hasDocument()
  {
    return document != null;
  }

  public boolean isDirty()
  {
    return document != null && document.isDirty();
  }

  public CertificateRecord getSelectedRecord()
  {
    return selectedRecord;
  }

  public String getStatusText()
  {
    return statusText;
  }

  public String getTabTitle()
  {
    return tabTitle;
  }

  public void addPropertyChangeListener(PropertyChangeListener listener)
  {
    pcs.addPropertyChangeListener(listener);
  }

  public void removePropertyChangeListener(PropertyChangeListener listener)
  {
    pcs.removePropertyChangeListener(listener);
  }

  public boolean checkUnsavedChanges()
  {
    return document == null || !document.isDirty() || Dialogs.confirmUnsavedChanges(owner);
  }

  public void openTruststore(Path path)
  {
    char[] prefill = sessionService.loadPassword(path).orElse(null);
    Optional<char[]> password = Dialogs.promptPassword(owner, "打开信任库", "请输入密码：" + path.getFileName(), prefill);
    if(password.isEmpty())
    {
      return;
    }
    try
    {
      PasswordAwareLoadResult result = trustStoreService.load(path, password.get());
      setDocument(result.document());
      sessionService.savePassword(path, password.get());
      status("已打开 " + path.getFileName() + "，类型：" + result.detectedType());
    }
    catch(Exception ex)
    {
      Dialogs.showError(owner, "打开信任库失败", "无法打开信任库。请检查密码和文件类型，默认证书库密码通常为 'changeit'。", ex);
      status("打开失败：" + path.getFileName());
    }
  }

  public void saveCurrent(boolean saveAs)
  {
    if(document == null)
    {
      return;
    }
    Path target = document.getPath();
    if(saveAs || target == null)
    {
      JFileChooser chooser = Dialogs.createStoreChooser();
      if(chooser.showSaveDialog(owner) != JFileChooser.APPROVE_OPTION)
      {
        return;
      }
      target = chooser.getSelectedFile().toPath();
    }
    Optional<char[]> pw = Dialogs.promptPassword(owner, "保存信任库", "请输入保存文件的密码");
    if(pw.isEmpty())
    {
      return;
    }
    try
    {
      if(Files.exists(target))
      {
        backupService.createBackup(target);
      }
      trustStoreService.save(document, target, pw.get());
      sessionService.savePassword(target, pw.get());
      status("已保存 " + target.getFileName());
      refreshChrome();
    }
    catch(Exception ex)
    {
      Dialogs.showError(owner, "保存失败", "无法保存信任库。", ex);
    }
  }

  public void importFromDialog()
  {
    if(document == null)
    {
      return;
    }
    JFileChooser chooser = Dialogs.createCertificateChooser();
    if(chooser.showOpenDialog(owner) != JFileChooser.APPROVE_OPTION)
    {
      return;
    }
    java.io.File[] files = chooser.getSelectedFiles();
    if(files == null || files.length == 0)
    {
      // Single selection fallback
      java.io.File single = chooser.getSelectedFile();
      if(single != null)
      {
        files = new java.io.File[] { single };
      }
      else
      {
        return;
      }
    }
    for(java.io.File file : files)
    {
      importCertificatePath(file.toPath());
    }
  }

  public void deleteSelected()
  {
    CertificateRecord record = selectedRecord;
    if(document == null || record == null)
    {
      return;
    }
    if(!Dialogs.confirmDelete(owner, record))
    {
      return;
    }
    try
    {
      trustStoreService.deleteAlias(document, record.alias());
      status("已删除 " + record.alias());
      updateBanner();
      refreshChrome();
    }
    catch(Exception ex)
    {
      Dialogs.showError(owner, "删除失败", "无法删除选中的证书。", ex);
    }
  }

  public void exportSelected()
  {
    CertificateRecord record = selectedRecord;
    if(record == null)
    {
      return;
    }
    JFileChooser chooser = Dialogs.createExportChooser(record.alias());
    if(chooser.showSaveDialog(owner) != JFileChooser.APPROVE_OPTION)
    {
      return;
    }
    java.io.File target = chooser.getSelectedFile();
    boolean pem = target.getName().toLowerCase(Locale.ROOT).endsWith(".pem");
    try
    {
      trustStoreService.exportCertificate(record.certificate(), target.toPath(), pem);
      status("已导出证书 " + record.alias());
    }
    catch(Exception ex)
    {
      Dialogs.showError(owner, "导出失败", "无法导出证书。", ex);
    }
  }

  public void exportPublicKey()
  {
    CertificateRecord record = selectedRecord;
    if(record == null)
    {
      return;
    }
    JFileChooser chooser = Dialogs.createPublicKeyExportChooser(record.alias());
    if(chooser.showSaveDialog(owner) != JFileChooser.APPROVE_OPTION)
    {
      return;
    }
    java.io.File target = chooser.getSelectedFile();
    boolean pem = !target.getName().toLowerCase(Locale.ROOT).endsWith(".der");
    try
    {
      trustStoreService.exportPublicKey(record.certificate(), target.toPath(), pem);
      status("已导出公钥 " + record.alias());
    }
    catch(Exception ex)
    {
      Dialogs.showError(owner, "导出失败", "无法导出公钥。", ex);
    }
  }

  /* ---- Static helpers used by MainWindow for drag-and-drop ---- */

  public void exportPrivateKey()
  {
    CertificateRecord record = selectedRecord;
    if(record == null)
    {
      return;
    }
    PrivateKey key = record.privateKey();
    if(key == null)
    {
      Optional<char[]> keyPw = Dialogs.promptPassword(owner, "私钥密码", "私钥密码可能与信任库密码不同，请输入私钥密码：");
      if(keyPw.isEmpty())
      {
        return;
      }
      try
      {
        key = trustStoreService.loadPrivateKey(document, record.alias(), keyPw.get());
      }
      catch(Exception ex)
      {
        Dialogs.showError(owner, "加载私钥失败", "无法使用提供的密码加载私钥。", ex);
        return;
      }
    }
    if(!Dialogs.confirmPrivateKeyExport(owner, record.alias()))
    {
      return;
    }
    JFileChooser chooser = Dialogs.createPrivateKeyExportChooser(record.alias());
    if(chooser.showSaveDialog(owner) != JFileChooser.APPROVE_OPTION)
    {
      return;
    }
    java.io.File target = chooser.getSelectedFile();
    boolean pem = !target.getName().toLowerCase(Locale.ROOT).endsWith(".der");
    try
    {
      trustStoreService.exportPrivateKey(key, target.toPath(), pem);
      status("已导出私钥 " + record.alias());
    }
    catch(Exception ex)
    {
      Dialogs.showError(owner, "导出失败", "无法导出私钥。", ex);
    }
  }

  public void restoreBackup()
  {
    if(document == null || document.getPath() == null)
    {
      Dialogs.showInfo(owner, "恢复备份", "请先将信任库保存到磁盘再进行恢复。");
      return;
    }
    try
    {
      List<BackupRecord> backups = backupService.listBackups(document.getPath());
      if(backups.isEmpty())
      {
        Dialogs.showInfo(owner, "恢复备份", "未找到该信任库的备份。");
        return;
      }
      Optional<BackupRecord> choice = Dialogs.chooseBackup(owner, backups);
      if(choice.isEmpty())
      {
        return;
      }
      BackupRecord backupRecord = choice.get();
      if(!Dialogs.confirmRestore(owner, backupRecord))
      {
        return;
      }
      backupService.restoreBackup(backupRecord);
      PasswordAwareLoadResult reloaded = trustStoreService.load(document.getPath(), document.getPassword());
      setDocument(reloaded.document());
      status("已恢复备份 " + backupRecord.backupPath().getFileName());
    }
    catch(Exception ex)
    {
      Dialogs.showError(owner, "恢复失败", "无法恢复选中的备份。", ex);
    }
  }

  /* ---- UI construction ---- */

  public void importCertificatePath(Path path)
  {
    if(document == null)
    {
      return;
    }
    try
    {
      List<X509Certificate> certs = trustStoreService.parseCertificates(path);
      for(int i = 0; i < certs.size(); i++)
      {
        X509Certificate cert = certs.get(i);
        String chosenAlias = Dialogs.promptAlias(owner, inferAlias(path, cert, i)).orElse(null);
        if(chosenAlias == null)
        {
          return;
        }
        boolean replace = false;
        while(trustStoreService.aliasExists(document, chosenAlias))
        {
          Dialogs.AliasConflictResolution resolution = Dialogs.promptAliasConflict(owner, chosenAlias);
          if(resolution == Dialogs.AliasConflictResolution.CANCEL)
          {
            return;
          }
          if(resolution == Dialogs.AliasConflictResolution.REPLACE)
          {
            replace = true;
            break;
          }
          chosenAlias = Dialogs.promptAlias(owner, chosenAlias + "-copy").orElse(null);
          if(chosenAlias == null)
          {
            return;
          }
        }

        CertificateRecord preview =
            new CertificateRecord(chosenAlias, "受信任的证书", CertificateFormatter.shortDn(cert.getSubjectX500Principal().getName()),
                CertificateFormatter.shortDn(cert.getIssuerX500Principal().getName()),
                cert.getSerialNumber().toString(16).toUpperCase(Locale.ROOT), cert.getNotBefore().toInstant(),
                cert.getNotAfter().toInstant(), cert.getSigAlgName(), FingerprintUtils.fingerprintSha1(cert),
                FingerprintUtils.fingerprintSha256(cert), cert, cert.getNotAfter().toInstant().isBefore(Instant.now()),
                cert.getNotBefore().toInstant().isAfter(Instant.now()), 1, path, null);
        if(!Dialogs.confirmImport(owner, preview))
        {
          continue;
        }
        trustStoreService.importCertificate(document, chosenAlias, cert, replace);
        status("已导入 " + chosenAlias);
        updateBanner();
        refreshChrome();
      }
    }
    catch(Exception ex)
    {
      Dialogs.showError(owner, "导入失败", "无法导入证书文件。", ex);
      status("导入失败：" + path.getFileName());
    }
  }

  private void buildUi()
  {
    // Banner
    bannerLabel.setOpaque(true);
    bannerLabel.setBackground(new Color(248, 231, 174));
    bannerLabel.setForeground(new Color(94, 67, 6));
    bannerLabel.setFont(bannerLabel.getFont().deriveFont(Font.BOLD));
    bannerLabel.setBorder(BorderFactory.createEmptyBorder(10, 16, 10, 16));
    bannerLabel.setVisible(false);

    // Search field
    searchField.putClientProperty("JTextField.placeholderText", "搜索别名、主题、颁发者、序列号或指纹");

    // Table
    configureTable();

    // Chain tree
    configureChainTree();

    // Details area
    detailsArea.setEditable(false);
    detailsArea.setLineWrap(true);
    detailsArea.setWrapStyleWord(true);
    detailsArea.setFont(new Font("Cascadia Mono", Font.PLAIN, 12));

    // Chain panel
    JPanel chainPanel = new JPanel(new BorderLayout(8, 8));
    chainPanel.setBackground(new Color(250, 245, 245));
    chainPanel.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(new Color(212, 184, 184), 1, true),
        BorderFactory.createEmptyBorder(14, 14, 14, 14)));
    JLabel chainTitle = new JLabel("信任链");
    chainTitle.setFont(chainTitle.getFont().deriveFont(Font.BOLD, 15f));
    chainTitle.setForeground(new Color(77, 26, 26));
    JPanel chainTop = new JPanel(new BorderLayout(0, 4));
    chainTop.setOpaque(false);
    chainTop.add(chainTitle, BorderLayout.NORTH);
    chainTop.add(chainSummaryLabel, BorderLayout.SOUTH);
    chainPanel.add(chainTop, BorderLayout.NORTH);
    chainTreeScroll.setPreferredSize(new Dimension(0, CHAIN_PANEL_MIN_HEIGHT));
    chainTreeScroll.setBorder(BorderFactory.createLineBorder(new Color(216, 194, 194)));
    chainPanel.add(chainTreeScroll, BorderLayout.CENTER);

    // Details section title
    JLabel detailsTitle = new JLabel("证书详情");
    detailsTitle.setFont(detailsTitle.getFont().deriveFont(Font.BOLD, 15f));
    detailsTitle.setForeground(new Color(77, 26, 26));

    // Button panel
    JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
    buttonPanel.add(copyButton);
    buttonPanel.add(detailExportButton);
    buttonPanel.add(exportPublicKeyButton);
    buttonPanel.add(exportPrivateKeyButton);
    exportPublicKeyButton.setVisible(false);
    exportPrivateKeyButton.setVisible(false);

    // Right-side details box
    JPanel detailsBox = new JPanel(new BorderLayout(0, 10));
    detailsBox.setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));
    detailsBox.add(chainPanel, BorderLayout.NORTH);
    JPanel detailsContent = new JPanel(new BorderLayout(0, 8));
    detailsContent.add(detailsTitle, BorderLayout.NORTH);
    detailsContent.add(new JScrollPane(detailsArea), BorderLayout.CENTER);
    detailsContent.add(buttonPanel, BorderLayout.SOUTH);
    detailsBox.add(detailsContent, BorderLayout.CENTER);

    // Left-side center box
    JPanel centerBox = new JPanel(new BorderLayout(0, 10));
    centerBox.setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));
    centerBox.add(searchField, BorderLayout.NORTH);
    centerBox.add(new JScrollPane(table), BorderLayout.CENTER);

    // Split pane
    JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, centerBox, detailsBox);
    splitPane.setDividerLocation(0.58);
    splitPane.setResizeWeight(0.58);

    root.add(bannerLabel, BorderLayout.NORTH);
    root.add(splitPane, BorderLayout.CENTER);
  }

  private void configureChainTree()
  {
    chainTree.setRootVisible(false);
    chainTree.setRowHeight(CHAIN_ROW_HEIGHT);
    chainTree.setCellRenderer(new DefaultTreeCellRenderer()
    {
      @Override
      public Component getTreeCellRendererComponent(JTree tree, Object value, boolean sel, boolean expanded, boolean leaf, int row,
          boolean hasFocus)
      {
        if(value instanceof DefaultMutableTreeNode node && node.getUserObject() instanceof ChainAnalysisNode(
            String alias, String subject, String role, List<String> badges
        ))
        {
          JPanel panel = new JPanel();
          panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
          panel.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(new Color(221, 197, 197), 1, true),
              BorderFactory.createEmptyBorder(8, 10, 8, 10)));
          panel.setBackground(sel ? new Color(230, 240, 250) : Color.WHITE);

          JLabel subjectLabel = new JLabel(subject);
          subjectLabel.setFont(subjectLabel.getFont().deriveFont(Font.BOLD));
          subjectLabel.setForeground(new Color(77, 26, 26));
          subjectLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

          String metaText = role + (alias == null ? "" : "  |  alias: " + alias);
          JLabel metaLabel = new JLabel(metaText);
          metaLabel.setFont(metaLabel.getFont().deriveFont(11f));
          metaLabel.setForeground(new Color(122, 90, 90));
          metaLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

          JPanel badgePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
          badgePanel.setOpaque(false);
          badgePanel.setAlignmentX(Component.LEFT_ALIGNMENT);
          for(String badge : badges)
          {
            JLabel bl = new JLabel(badge);
            bl.setFont(bl.getFont().deriveFont(Font.BOLD, 11f));
            bl.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6));
            bl.setOpaque(true);
            applyBadgeStyle(bl, badge);
            badgePanel.add(bl);
          }

          panel.add(subjectLabel);
          panel.add(Box.createVerticalStrut(2));
          panel.add(metaLabel);
          panel.add(Box.createVerticalStrut(2));
          panel.add(badgePanel);
          return panel;
        }
        return super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, hasFocus);
      }
    });
  }

  private void applyBadgeStyle(JLabel label, String badge)
  {
    String normalized = badge.toLowerCase(Locale.ROOT);
    if(normalized.contains("trusted") || normalized.contains("root") || normalized.contains("ca") || normalized.contains("verified"))
    {
      label.setBackground(new Color(212, 237, 218));
      label.setForeground(new Color(21, 87, 36));
    }
    else if(normalized.contains("self-signed") || normalized.contains("likely"))
    {
      label.setBackground(new Color(228, 238, 249));
      label.setForeground(new Color(31, 79, 134));
    }
    else if(normalized.contains("missing") || normalized.contains("expired"))
    {
      label.setBackground(new Color(248, 215, 218));
      label.setForeground(new Color(114, 28, 36));
    }
    else if(normalized.contains("end") || normalized.contains("not-yet") || normalized.contains("not yet"))
    {
      label.setBackground(new Color(255, 243, 205));
      label.setForeground(new Color(133, 100, 4));
    }
    else
    {
      label.setBackground(new Color(230, 230, 230));
      label.setForeground(Color.DARK_GRAY);
    }
  }

  /* ---- State binding ---- */

  private void configureTable()
  {
    table.setAutoCreateRowSorter(false);
    rowSorter = new TableRowSorter<>(tableModel);
    table.setRowSorter(rowSorter);
    table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
    table.setFillsViewportHeight(true);
    table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);

    // Set preferred column widths
    int[] widths = { 160, 140, 220, 220, 160, 170, 170, 140, 250, 360 };
    for(int i = 0; i < widths.length && i < table.getColumnCount(); i++)
    {
      table.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
    }

    // Custom renderer for expired/future row highlighting
    DefaultTableCellRenderer highlightRenderer = new DefaultTableCellRenderer()
    {
      @Override
      public Component getTableCellRendererComponent(JTable tbl, Object value, boolean isSelected, boolean hasFocus, int row, int column)
      {
        Component c = super.getTableCellRendererComponent(tbl, value, isSelected, hasFocus, row, column);
        if(!isSelected)
        {
          int modelRow = tbl.convertRowIndexToModel(row);
          CertificateRecord record = tableModel.getRecordAt(modelRow);
          if(record != null && record.expired())
          {
            c.setBackground(new Color(253, 234, 234));
          }
          else if(record != null && record.notYetValid())
          {
            c.setBackground(new Color(255, 244, 219));
          }
          else
          {
            c.setBackground(tbl.getBackground());
          }
        }
        return c;
      }
    };
    for(int i = 0; i < table.getColumnCount(); i++)
    {
      table.getColumnModel().getColumn(i).setCellRenderer(highlightRenderer);
    }
  }

  /* ---- Rendering ---- */

  private void bindState()
  {
    // Buttons disabled until a record is selected
    detailExportButton.setEnabled(false);
    copyButton.setEnabled(false);
    exportPublicKeyButton.setEnabled(false);
    exportPrivateKeyButton.setEnabled(false);

    // Table selection → update selectedRecord
    table.getSelectionModel().addListSelectionListener(e -> {
      if(!e.getValueIsAdjusting())
      {
        int viewRow = table.getSelectedRow();
        CertificateRecord old = selectedRecord;
        if(viewRow >= 0)
        {
          int modelRow = table.convertRowIndexToModel(viewRow);
          selectedRecord = tableModel.getRecordAt(modelRow);
        }
        else
        {
          selectedRecord = null;
        }
        pcs.firePropertyChange("selectedRecord", old, selectedRecord);
        renderDetails(selectedRecord);
      }
    });

    // Search field → filter
    searchField.getDocument().addDocumentListener(new DocumentListener()
    {
      @Override
      public void insertUpdate(DocumentEvent e)
      {
        updateFilter();
      }

      @Override
      public void removeUpdate(DocumentEvent e)
      {
        updateFilter();
      }

      @Override
      public void changedUpdate(DocumentEvent e)
      {
        updateFilter();
      }
    });

    // Button actions
    copyButton.addActionListener(e -> copyDetails());
    detailExportButton.addActionListener(e -> exportSelected());
    exportPublicKeyButton.addActionListener(e -> exportPublicKey());
    exportPrivateKeyButton.addActionListener(e -> exportPrivateKey());
  }

  private void renderDetails(CertificateRecord record)
  {
    boolean hasRecord = record != null;
    detailExportButton.setEnabled(hasRecord);
    copyButton.setEnabled(hasRecord);

    if(record == null)
    {
      detailsArea.setText("");
      clearChainView();
      exportPublicKeyButton.setVisible(false);
      exportPrivateKeyButton.setVisible(false);
      return;
    }
    exportPublicKeyButton.setVisible(true);
    exportPublicKeyButton.setEnabled(true);
    boolean isKeyEntry = "Key Entry".equals(record.entryType());
    exportPrivateKeyButton.setVisible(isKeyEntry);
    exportPrivateKeyButton.setEnabled(isKeyEntry);
    try
    {
      ChainAnalysisResult analysis = document == null ? null : chainAnalysisService.analyze(document, record);
      String details = CertificateFormatter.formatCertificateDetails(record.certificate(), record.privateKey(), analysis);
      if(isKeyEntry && record.privateKey() == null)
      {
        details += "\n=== 私钥信息 ===\n" + "该条目包含私钥，但私钥密码可能与信任库密码不同，未能自动加载。\n"
            + "请使用下方\"导出私钥\"按钮，输入正确的私钥密码后即可查看和导出。\n";
      }
      detailsArea.setText(details);
      detailsArea.setCaretPosition(0);
      renderChain(analysis);
    }
    catch(Exception ex)
    {
      detailsArea.setText("无法渲染证书详情：" + ex.getMessage());
      clearChainView();
    }
  }

  private void renderChain(ChainAnalysisResult analysis)
  {
    if(analysis == null || analysis.nodes().isEmpty())
    {
      clearChainView();
      return;
    }
    DefaultMutableTreeNode invisibleRoot = new DefaultMutableTreeNode("root");
    invisibleRoot.add(buildVisibleChain(analysis.nodes(), 0));
    chainTree.setModel(new DefaultTreeModel(invisibleRoot));
    // Expand all
    for(int i = 0; i < chainTree.getRowCount(); i++)
    {
      chainTree.expandRow(i);
    }
    int h = estimateChainHeight(analysis.nodes().size());
    chainTreeScroll.setPreferredSize(new Dimension(0, h));
    chainTreeScroll.revalidate();
    chainSummaryLabel.setText(chainSummaryText(analysis));
  }

  private int estimateChainHeight(int nodeCount)
  {
    int estimated = 20 + (nodeCount * CHAIN_ROW_HEIGHT);
    return Math.max(CHAIN_PANEL_MIN_HEIGHT, Math.min(CHAIN_PANEL_MAX_HEIGHT, estimated));
  }

  private DefaultMutableTreeNode buildVisibleChain(List<ChainAnalysisNode> nodes, int index)
  {
    DefaultMutableTreeNode treeNode = new DefaultMutableTreeNode(nodes.get(index));
    if(index + 1 < nodes.size())
    {
      treeNode.add(buildVisibleChain(nodes, index + 1));
    }
    return treeNode;
  }

  private String chainSummaryText(ChainAnalysisResult analysis)
  {
    if(analysis.chainBuildComplete())
    {
      return "信任链已成功构建至信任锚点 " + analysis.trustAnchorAlias() + "。";
    }
    if(analysis.missingIssuer())
    {
      return "信任链不完整，在此信任库中未找到匹配的颁发者。";
    }
    return "该证书的信任链信息不完整。";
  }

  /* ---- Helpers ---- */

  private void clearChainView()
  {
    chainTree.setModel(null);
    chainTreeScroll.setPreferredSize(new Dimension(0, CHAIN_PANEL_MIN_HEIGHT));
    chainTreeScroll.revalidate();
    chainSummaryLabel.setText("选择一个证书以查看其信任链。");
  }

  private void refreshChrome()
  {
    String oldTitle = tabTitle;
    if(document == null)
    {
      tabTitle = "新标签页";
    }
    else
    {
      tabTitle = document.getDisplayName() + (document.isDirty() ? " *" : "");
    }
    pcs.firePropertyChange("tabTitle", oldTitle, tabTitle);
  }

  private void updateBanner()
  {
    if(document == null)
    {
      bannerLabel.setVisible(false);
      return;
    }
    long expiredCount = document.getCertificates().stream().filter(CertificateRecord::expired).count();
    long futureCount = document.getCertificates().stream().filter(CertificateRecord::notYetValid).count();
    if(expiredCount == 0 && futureCount == 0)
    {
      bannerLabel.setVisible(false);
      return;
    }
    bannerLabel.setText(expiredCount + " 个已过期证书，" + futureCount + " 个尚未生效证书");
    bannerLabel.setVisible(true);
  }

  private void updateFilter()
  {
    String text = searchField.getText();
    if(text == null || text.isBlank())
    {
      rowSorter.setRowFilter(null);
    }
    else
    {
      String normalized = text.toLowerCase(Locale.ROOT);
      rowSorter.setRowFilter(new javax.swing.RowFilter<CertificateTableModel, Integer>()
      {
        @Override
        public boolean include(Entry<? extends CertificateTableModel, ? extends Integer> entry)
        {
          int row = entry.getIdentifier();
          CertificateRecord r = tableModel.getRecordAt(row);
          return r != null && matchesFilter(r, normalized);
        }
      });
    }
  }

  private boolean matchesFilter(CertificateRecord record, String filter)
  {
    return contains(record.alias(), filter) || contains(record.subject(), filter) || contains(record.issuer(), filter) || contains(
        record.serialNumber(), filter) || contains(record.sha1(), filter) || contains(record.sha256(), filter);
  }

  private boolean contains(String value, String filter)
  {
    return value != null && value.toLowerCase(Locale.ROOT).contains(filter);
  }

  private void copyDetails()
  {
    if(selectedRecord == null)
    {
      return;
    }
    StringSelection ss = new StringSelection(detailsArea.getText());
    Toolkit.getDefaultToolkit().getSystemClipboard().setContents(ss, null);
    status("已复制 " + selectedRecord.alias() + " 的详情");
  }

  private String inferAlias(Path path, X509Certificate cert, int index)
  {
    String baseName = path.getFileName().toString().replaceFirst("\\.[^.]+$", "");
    String subject =
        CertificateFormatter.shortDn(cert.getSubjectX500Principal().getName()).replace("CN=", "").trim().replaceAll("[^a-zA-Z0-9._-]+", "-")
            .toLowerCase(Locale.ROOT);
    String alias = subject.isBlank() ? baseName : subject;
    return index == 0 ? alias : alias + "-" + (index + 1);
  }

  private void status(String message)
  {
    String old = statusText;
    statusText = message;
    pcs.firePropertyChange("statusText", old, statusText);
  }

  /* ---- Table model ---- */

  private class CertificateTableModel extends AbstractTableModel
  {
    private static final String[] COLUMNS =
        { "别名", "条目类型", "主题", "颁发者", "序列号", "有效期起", "有效期止", "签名算法", "SHA-1", "SHA-256" };
    private List<CertificateRecord> data = Collections.emptyList();

    void setData(List<CertificateRecord> records)
    {
      this.data = records == null ? Collections.emptyList() : new ArrayList<>(records);
      fireTableDataChanged();
    }

    void refresh()
    {
      if(document != null)
      {
        setData(document.getCertificates());
      }
      else
      {
        setData(null);
      }
    }

    CertificateRecord getRecordAt(int modelRow)
    {
      if(modelRow >= 0 && modelRow < data.size())
      {
        return data.get(modelRow);
      }
      return null;
    }

    @Override
    public int getRowCount()
    {
      return data.size();
    }

    @Override
    public int getColumnCount()
    {
      return COLUMNS.length;
    }

    @Override
    public String getColumnName(int column)
    {
      return COLUMNS[column];
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex)
    {
      CertificateRecord r = data.get(rowIndex);
      return switch(columnIndex)
      {
        case 0 -> r.alias();
        case 1 -> r.entryType();
        case 2 -> r.subject();
        case 3 -> r.issuer();
        case 4 -> r.serialNumber();
        case 5 -> CertificateFormatter.DATE_FORMAT.format(r.validFrom());
        case 6 -> CertificateFormatter.DATE_FORMAT.format(r.validTo());
        case 7 -> r.signatureAlgorithm();
        case 8 -> r.sha1();
        case 9 -> r.sha256();
        default -> "";
      };
    }
  }
}
