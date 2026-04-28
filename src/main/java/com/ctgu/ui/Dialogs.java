package com.ctgu.ui;

import com.ctgu.model.BackupRecord;
import com.ctgu.model.CertificateRecord;
import com.ctgu.util.CertificateFormatter;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.io.File;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Optional;

/**
 * @author lihuahui
 * @version 1.0
 * @description: 对话框工具类，封装了应用中使用的各种对话框的创建和显示逻辑，提供统一的接口供 UI 层调用
 * @date 2026-04-10 14:01
 */
public final class Dialogs
{
  private static final DateTimeFormatter BACKUP_TIME_FORMAT =
      DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

  private Dialogs()
  {
  }

  public static Optional<char[]> promptPassword(Component owner, String title, String header)
  {
    return promptPassword(owner, title, header, null);
  }

  public static Optional<char[]> promptPassword(Component owner, String title, String header, char[] prefill)
  {
    JPasswordField passwordField = new JPasswordField(20);
    if(prefill != null && prefill.length > 0)
    {
      passwordField.setText(new String(prefill));
    }
    JPanel panel = new JPanel(new BorderLayout(8, 8));
    panel.add(new JLabel(header), BorderLayout.NORTH);
    JPanel fieldPanel = new JPanel(new BorderLayout(8, 0));
    fieldPanel.add(new JLabel("密码:"), BorderLayout.WEST);
    fieldPanel.add(passwordField, BorderLayout.CENTER);
    panel.add(fieldPanel, BorderLayout.CENTER);

    int result = JOptionPane.showConfirmDialog(owner, panel, title, JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
    if(result == JOptionPane.OK_OPTION)
    {
      return Optional.of(passwordField.getPassword());
    }
    return Optional.empty();
  }

  public static Optional<String> promptAlias(Component owner, String suggestedAlias)
  {
    String input = (String)JOptionPane.showInputDialog(owner, "为导入的证书选择一个别名", "证书别名", JOptionPane.PLAIN_MESSAGE, null, null,
        suggestedAlias);
    if(input != null && !input.trim().isEmpty())
    {
      return Optional.of(input.trim());
    }
    return Optional.empty();
  }

  public static boolean confirmDelete(Component owner, CertificateRecord record)
  {
    int result =
        JOptionPane.showConfirmDialog(owner, "确定要删除选中的证书吗？\n\n别名：" + record.alias() + "\n主题：" + record.subject(), "删除证书",
            JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
    return result == JOptionPane.OK_OPTION;
  }

  public static AliasConflictResolution promptAliasConflict(Component owner, String alias)
  {
    String[] options = { "替换现有", "选择新别名", "取消" };
    int result = JOptionPane.showOptionDialog(owner, "别名 \"" + alias + "\" 已被使用。", "别名已存在", JOptionPane.DEFAULT_OPTION,
        JOptionPane.WARNING_MESSAGE, null, options, options[2]);
    if(result == 0)
    {
      return AliasConflictResolution.REPLACE;
    }
    if(result == 1)
    {
      return AliasConflictResolution.CHOOSE_NEW;
    }
    return AliasConflictResolution.CANCEL;
  }

  public static boolean confirmImport(Component owner, CertificateRecord previewRecord)
  {
    String text = "别名：" + previewRecord.alias() + "\n主题：" + previewRecord.certificate().getSubjectX500Principal().getName() + "\n颁发者："
        + previewRecord.certificate().getIssuerX500Principal().getName() + "\n有效期止：" + CertificateFormatter.DATE_FORMAT.format(
        previewRecord.validTo());
    JTextArea area = new JTextArea(text);
    area.setEditable(false);
    area.setLineWrap(true);
    area.setWrapStyleWord(true);
    area.setColumns(50);
    area.setRows(6);
    JScrollPane scrollPane = new JScrollPane(area);
    scrollPane.setPreferredSize(new Dimension(500, 150));

    int result = JOptionPane.showConfirmDialog(owner, scrollPane, "导入证书 - 确定将此证书导入信任库吗？", JOptionPane.OK_CANCEL_OPTION,
        JOptionPane.QUESTION_MESSAGE);
    return result == JOptionPane.OK_OPTION;
  }

  public static Optional<BackupRecord> chooseBackup(Component owner, List<BackupRecord> backups)
  {
    JDialog dialog = new JDialog(SwingUtilities.getWindowAncestor(owner), "恢复备份", Dialog.ModalityType.APPLICATION_MODAL);
    dialog.setLayout(new BorderLayout(10, 10));
    dialog.setSize(820, 420);
    dialog.setLocationRelativeTo(owner);

    DefaultListModel<BackupRecord> listModel = new DefaultListModel<>();
    backups.forEach(listModel::addElement);
    JList<BackupRecord> list = new JList<>(listModel);
    list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
    list.setCellRenderer(new DefaultListCellRenderer()
    {
      @Override
      public Component getListCellRendererComponent(JList<?> jList, Object value, int index, boolean isSelected, boolean cellHasFocus)
      {
        super.getListCellRendererComponent(jList, value, index, isSelected, cellHasFocus);
        if(value instanceof BackupRecord br)
        {
          setText(BACKUP_TIME_FORMAT.format(br.createdAt()) + "  |  " + br.backupPath().getFileName() + "  |  " + br.size() + " 字节");
        }
        return this;
      }
    });
    if(!backups.isEmpty())
    {
      list.setSelectedIndex(0);
    }

    JPanel topPanel = new JPanel(new BorderLayout());
    topPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 0, 10));
    topPanel.add(new JLabel("选择要恢复的备份:"), BorderLayout.NORTH);

    JScrollPane scrollPane = new JScrollPane(list);
    scrollPane.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));

    JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
    buttonPanel.setBorder(BorderFactory.createEmptyBorder(0, 10, 10, 10));
    JButton okButton = new JButton("确定");
    JButton cancelButton = new JButton("取消");
    okButton.setEnabled(!backups.isEmpty());
    list.addListSelectionListener(e -> okButton.setEnabled(list.getSelectedValue() != null));
    buttonPanel.add(okButton);
    buttonPanel.add(cancelButton);

    dialog.add(topPanel, BorderLayout.NORTH);
    dialog.add(scrollPane, BorderLayout.CENTER);
    dialog.add(buttonPanel, BorderLayout.SOUTH);

    final BackupRecord[] selected = { null };
    okButton.addActionListener(e -> {
      selected[0] = list.getSelectedValue();
      dialog.dispose();
    });
    cancelButton.addActionListener(e -> dialog.dispose());

    dialog.setVisible(true);
    return Optional.ofNullable(selected[0]);
  }

  public static boolean confirmRestore(Component owner, BackupRecord backupRecord)
  {
    int result = JOptionPane.showConfirmDialog(owner,
        "确定要用此备份覆盖当前信任库吗？\n\n备份：" + backupRecord.backupPath().getFileName() + "\n创建时间：" + BACKUP_TIME_FORMAT.format(
            backupRecord.createdAt()) + "\n目标：" + backupRecord.originalPath(), "恢复备份", JOptionPane.OK_CANCEL_OPTION,
        JOptionPane.WARNING_MESSAGE);
    return result == JOptionPane.OK_OPTION;
  }

  public static void showError(Component owner, String title, String message, Throwable throwable)
  {
    String fullMessage = message;
    if(throwable != null && throwable.getMessage() != null)
    {
      fullMessage += "\n\n详细信息：\n" + throwable.getMessage();
    }
    JTextArea area = new JTextArea(fullMessage);
    area.setEditable(false);
    area.setLineWrap(true);
    area.setWrapStyleWord(true);
    area.setColumns(50);
    area.setRows(8);
    JScrollPane sp = new JScrollPane(area);
    sp.setPreferredSize(new Dimension(500, 200));
    JOptionPane.showMessageDialog(owner, sp, title, JOptionPane.ERROR_MESSAGE);
  }

  public static void showInfo(Component owner, String title, String message)
  {
    JOptionPane.showMessageDialog(owner, message, title, JOptionPane.INFORMATION_MESSAGE);
  }

  public static boolean confirmUnsavedChanges(Component owner)
  {
    int result =
        JOptionPane.showConfirmDialog(owner, "您有未保存的更改。\n确定不保存就关闭吗？", "未保存的更改", JOptionPane.OK_CANCEL_OPTION,
            JOptionPane.WARNING_MESSAGE);
    return result == JOptionPane.OK_OPTION;
  }

  public static JFileChooser createStoreChooser()
  {
    JFileChooser chooser = new JFileChooser();
    chooser.setDialogTitle("打开信任库");
    chooser.setFileFilter(new FileNameExtensionFilter("信任库文件 (*.jks, *.p12, *.pkcs12)", "jks", "p12", "pkcs12", "cacerts"));
    chooser.setAcceptAllFileFilterUsed(true);
    return chooser;
  }

  public static JFileChooser createCertificateChooser()
  {
    JFileChooser chooser = new JFileChooser();
    chooser.setDialogTitle("导入证书");
    chooser.setMultiSelectionEnabled(true);
    chooser.setFileFilter(new FileNameExtensionFilter("证书文件 (*.cer, *.crt, *.pem, *.der)", "cer", "crt", "pem", "der"));
    chooser.setAcceptAllFileFilterUsed(true);
    return chooser;
  }

  public static JFileChooser createExportChooser(String alias)
  {
    JFileChooser chooser = new JFileChooser();
    chooser.setDialogTitle("导出证书");
    chooser.setSelectedFile(new File(alias + ".cer"));
    chooser.addChoosableFileFilter(new FileNameExtensionFilter("DER 证书 (*.cer)", "cer"));
    chooser.addChoosableFileFilter(new FileNameExtensionFilter("PEM 证书 (*.pem)", "pem"));
    chooser.setAcceptAllFileFilterUsed(false);
    return chooser;
  }

  public static JFileChooser createPublicKeyExportChooser(String alias)
  {
    JFileChooser chooser = new JFileChooser();
    chooser.setDialogTitle("导出公钥");
    chooser.setSelectedFile(new File(alias + "_pub.pem"));
    chooser.addChoosableFileFilter(new FileNameExtensionFilter("PEM 公钥 (*.pem)", "pem"));
    chooser.addChoosableFileFilter(new FileNameExtensionFilter("DER 公钥 (*.der)", "der"));
    chooser.setAcceptAllFileFilterUsed(false);
    return chooser;
  }

  public static JFileChooser createPrivateKeyExportChooser(String alias)
  {
    JFileChooser chooser = new JFileChooser();
    chooser.setDialogTitle("导出私钥 (PKCS#8)");
    chooser.setSelectedFile(new File(alias + "_key.pem"));
    chooser.addChoosableFileFilter(new FileNameExtensionFilter("PEM 私钥 (PKCS#8) (*.pem)", "pem"));
    chooser.addChoosableFileFilter(new FileNameExtensionFilter("DER 私钥 (PKCS#8) (*.der)", "der"));
    chooser.setAcceptAllFileFilterUsed(false);
    return chooser;
  }

  public static boolean confirmPrivateKeyExport(Component owner, String alias)
  {
    int result = JOptionPane.showConfirmDialog(owner, "即将导出私钥，请注意保密！\n\n别名：" + alias
            + "\n\n私钥一旦泄露，对应证书将失去安全保障。\n请确保导出后妥善保存，不要分享给他人。\n\n确定要导出此私钥吗？", "导出私钥 — 安全警告",
        JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
    return result == JOptionPane.OK_OPTION;
  }

  public enum AliasConflictResolution
  {
    CANCEL, REPLACE, CHOOSE_NEW
  }
}