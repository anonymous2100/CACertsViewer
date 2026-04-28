package com.ctgu.ui;

import com.ctgu.model.TrustStoreDocument;
import com.ctgu.service.*;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.dnd.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * @author lihuahui
 * @version 1.0
 * @description: 主窗口，负责整体界面布局、状态管理、事件协调等
 * @date 2026-04-10 14:04
 */
public class MainWindow extends JFrame
{
  private final TrustStoreService trustStoreService = new TrustStoreService();
  private final BackupService backupService = new BackupService();
  private final ChainAnalysisService chainAnalysisService = new ChainAnalysisService();
  private final SystemTrustStoreLocator trustStoreLocator = new SystemTrustStoreLocator();
  private final SessionService sessionService = new SessionService();

  private final JTabbedPane tabPane = new JTabbedPane();
  private KeystoreTabContent activeContent;

  private final JLabel statusLabel = new JLabel("打开一个信任库以开始。");
  private final JLabel pathLabel = new JLabel("未加载信任库");

  private final JButton openButton = new JButton("打开");
  private final JButton openDefaultButton = new JButton("打开默认证书库");
  private final JButton saveButton = new JButton("保存");
  private final JButton saveAsButton = new JButton("另存为");
  private final JButton importButton = new JButton("导入");
  private final JButton deleteButton = new JButton("删除");
  private final JButton restoreButton = new JButton("恢复");
  private final JButton exportButton = new JButton("导出");

  /* Listener re-attached when the active tab switches */
  private final PropertyChangeListener tabContentListener = this::onTabContentPropertyChange;

  public MainWindow()
  {
    super("证书库管理器");
    setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);
    setSize(1400, 900);
    setLocationRelativeTo(null);

    buildUi();
    bindState();
    registerEvents();
    addNewTab();
  }

  public void onShown()
  {
    List<Path> previousFiles = sessionService.loadOpenFiles();
    if(!previousFiles.isEmpty())
    {
      status("正在恢复上次会话（" + previousFiles.size() + " 个文件）...");
      Timer timer = new Timer(500, e -> restoreSession(previousFiles));
      timer.setRepeats(false);
      timer.start();
    }
    else
    {
      trustStoreLocator.locateDefaultCacerts().ifPresent(path -> status("检测到默认证书库：" + path));
    }
  }

  private void restoreSession(List<Path> files)
  {
    for(Path path : files)
    {
      openInTab(path);
    }
    // Clean up tabs where the user clicked Cancel (still empty)
    for(int i = tabPane.getTabCount() - 1; i >= 0; i--)
    {
      KeystoreTabContent content = getContentAt(i);
      if(content != null && !content.hasDocument())
      {
        tabPane.removeTabAt(i);
      }
    }
    if(tabPane.getTabCount() == 0)
    {
      addNewTab();
    }
  }

  /* ---- UI construction ---- */

  private void buildUi()
  {
    JToolBar toolBar = new JToolBar();
    toolBar.setFloatable(false);
    toolBar.setBackground(new Color(107, 26, 26));
    toolBar.setBorder(BorderFactory.createEmptyBorder(6, 10, 6, 10));

    styleToolbarButton(openDefaultButton, true);
    styleToolbarButton(openButton, true);
    styleToolbarButton(saveButton, false);
    styleToolbarButton(saveAsButton, false);
    styleToolbarButton(importButton, false);
    styleToolbarButton(deleteButton, false);
    styleToolbarButton(exportButton, false);
    styleToolbarButton(restoreButton, false);

    toolBar.add(openDefaultButton);
    toolBar.add(Box.createHorizontalStrut(4));
    toolBar.add(openButton);
    toolBar.addSeparator(new Dimension(12, 24));
    toolBar.add(saveButton);
    toolBar.add(Box.createHorizontalStrut(4));
    toolBar.add(saveAsButton);
    toolBar.addSeparator(new Dimension(12, 24));
    toolBar.add(importButton);
    toolBar.add(Box.createHorizontalStrut(4));
    toolBar.add(deleteButton);
    toolBar.add(Box.createHorizontalStrut(4));
    toolBar.add(exportButton);
    toolBar.addSeparator(new Dimension(12, 24));
    toolBar.add(restoreButton);

    add(toolBar, BorderLayout.NORTH);
    add(tabPane, BorderLayout.CENTER);

    JPanel statusBar = new JPanel(new BorderLayout());
    statusBar.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, new Color(212, 184, 184)),
        BorderFactory.createEmptyBorder(8, 16, 8, 16)));
    statusBar.setBackground(new Color(240, 226, 226));

    statusLabel.setForeground(new Color(77, 26, 26));
    statusLabel.setFont(statusLabel.getFont().deriveFont(Font.BOLD, 12f));
    pathLabel.setForeground(new Color(77, 26, 26));
    pathLabel.setFont(pathLabel.getFont().deriveFont(Font.BOLD, 12f));

    statusBar.add(statusLabel, BorderLayout.WEST);
    statusBar.add(pathLabel, BorderLayout.EAST);
    add(statusBar, BorderLayout.SOUTH);
  }

  private void styleToolbarButton(JButton button, boolean accent)
  {
    button.setFocusPainted(false);
    button.setBorderPainted(false);
    button.setForeground(new Color(252, 240, 240));
    button.setFont(button.getFont().deriveFont(Font.BOLD));
    button.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
    button.setMargin(new Insets(6, 12, 6, 12));
    if(accent)
    {
      button.setBackground(new Color(76, 175, 80, 90));
    }
    else
    {
      button.setBackground(new Color(255, 255, 255, 38));
    }
    button.setOpaque(true);
  }

  /* ---- State binding ---- */

  private void bindState()
  {
    tabPane.addChangeListener(e -> {
      detachListeners(activeContent);
      int idx = tabPane.getSelectedIndex();
      activeContent = idx >= 0 ? getContentAt(idx) : null;
      attachListeners(activeContent);
      syncStatus();
      updatePathLabel();
      updateToolbarState();
      updateFrameTitle();
    });
  }

  private void detachListeners(KeystoreTabContent content)
  {
    if(content == null)
    {
      return;
    }
    content.removePropertyChangeListener(tabContentListener);
  }

  private void attachListeners(KeystoreTabContent content)
  {
    if(content == null)
    {
      return;
    }
    content.addPropertyChangeListener(tabContentListener);
  }

  private void onTabContentPropertyChange(PropertyChangeEvent evt)
  {
    switch(evt.getPropertyName())
    {
    case "statusText" -> syncStatus();
    case "document", "dirty" ->
    {
      updatePathLabel();
      updateToolbarState();
      updateFrameTitle();
      int idx = indexOfContent(activeContent);
      if(idx >= 0)
      {
        updateTabTitle(idx, activeContent);
      }
    }
    case "selectedRecord" -> updateToolbarState();
    case "tabTitle" ->
    {
      int idx = indexOfContent(activeContent);
      if(idx >= 0)
      {
        updateTabTitle(idx, activeContent);
      }
    }
    }
  }

  /* ---- Event registration ---- */

  private void registerEvents()
  {
    openButton.addActionListener(e -> openFromDialog());
    openDefaultButton.addActionListener(e -> trustStoreLocator.locateDefaultCacerts()
        .ifPresentOrElse(this::openInTab, () -> Dialogs.showInfo(this, "默认证书库", "未检测到默认证书库文件。")));
    saveButton.addActionListener(e -> withActive(c -> c.saveCurrent(false)));
    saveAsButton.addActionListener(e -> withActive(c -> c.saveCurrent(true)));
    importButton.addActionListener(e -> withActive(KeystoreTabContent::importFromDialog));
    deleteButton.addActionListener(e -> withActive(KeystoreTabContent::deleteSelected));
    exportButton.addActionListener(e -> withActive(KeystoreTabContent::exportSelected));
    restoreButton.addActionListener(e -> withActive(KeystoreTabContent::restoreBackup));

    // Drag and drop
    new DropTarget(this, new DropTargetAdapter()
    {
      @Override
      public void dragEnter(DropTargetDragEvent dtde)
      {
        if(dtde.isDataFlavorSupported(DataFlavor.javaFileListFlavor))
        {
          dtde.acceptDrag(DnDConstants.ACTION_COPY);
        }
        else
        {
          dtde.rejectDrag();
        }
      }

      @Override
      public void dragOver(DropTargetDragEvent dtde)
      {
        if(dtde.isDataFlavorSupported(DataFlavor.javaFileListFlavor))
        {
          dtde.acceptDrag(DnDConstants.ACTION_COPY);
        }
      }

      @Override
      @SuppressWarnings("unchecked")
      public void drop(DropTargetDropEvent dtde)
      {
        try
        {
          dtde.acceptDrop(DnDConstants.ACTION_COPY);
          List<File> files = (List<File>)dtde.getTransferable().getTransferData(DataFlavor.javaFileListFlavor);
          for(File file : files)
          {
            Path path = file.toPath();
            if(KeystoreTabContent.isStoreFile(path))
            {
              openInTab(path);
            }
            else if(KeystoreTabContent.isCertificateFile(path))
            {
              if(activeContent != null && activeContent.hasDocument())
              {
                activeContent.importCertificatePath(path);
              }
            }
          }
          dtde.dropComplete(true);
        }
        catch(Exception ex)
        {
          dtde.dropComplete(false);
        }
      }
    });

    addWindowListener(new WindowAdapter()
    {
      @Override
      public void windowClosing(WindowEvent e)
      {
        handleCloseRequest();
      }
    });
  }

  /* ---- Tab management ---- */

  private int addNewTab()
  {
    KeystoreTabContent content = new KeystoreTabContent(this, trustStoreService, backupService, chainAnalysisService, sessionService);
    JComponent panel = content.getContent();
    int idx = tabPane.getTabCount();
    tabPane.addTab("新标签页", panel);
    tabPane.setTabComponentAt(idx, createTabHeader(content));
    tabPane.setSelectedIndex(idx);
    return idx;
  }

  private JPanel createTabHeader(KeystoreTabContent content)
  {
    JPanel header = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
    header.setOpaque(false);
    JLabel titleLabel = new JLabel(content.getTabTitle());
    titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD));

    content.addPropertyChangeListener(evt -> {
      if("tabTitle".equals(evt.getPropertyName()))
      {
        titleLabel.setText((String)evt.getNewValue());
      }
    });

    JButton closeBtn = new JButton("×");
    closeBtn.setMargin(new Insets(0, 4, 0, 4));
    closeBtn.setFocusPainted(false);
    closeBtn.setBorderPainted(false);
    closeBtn.setContentAreaFilled(false);
    closeBtn.setFont(closeBtn.getFont().deriveFont(14f));
    closeBtn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
    closeBtn.addActionListener(e -> {
      int idx = indexOfContent(content);
      if(idx >= 0)
      {
        if(content.checkUnsavedChanges())
        {
          if(activeContent == content)
          {
            detachListeners(content);
          }
          tabPane.removeTabAt(idx);
          if(tabPane.getTabCount() == 0)
          {
            addNewTab();
          }
        }
      }
    });

    header.add(titleLabel);
    header.add(closeBtn);
    return header;
  }

  private void openFromDialog()
  {
    JFileChooser chooser = Dialogs.createStoreChooser();
    if(chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION)
    {
      openInTab(chooser.getSelectedFile().toPath());
    }
  }

  private void openInTab(Path path)
  {
    if(activeContent != null && !activeContent.hasDocument())
    {
      activeContent.openTruststore(path);
    }
    else
    {
      int idx = addNewTab();
      KeystoreTabContent content = getContentAt(idx);
      if(content != null)
      {
        content.openTruststore(path);
      }
    }
  }

  private void withActive(Consumer<KeystoreTabContent> action)
  {
    if(activeContent != null)
    {
      action.accept(activeContent);
    }
  }

  /* ---- Toolbar and chrome updates ---- */

  private void updateToolbarState()
  {
    boolean noDoc = activeContent == null || !activeContent.hasDocument();
    boolean noSelection = activeContent == null || activeContent.getSelectedRecord() == null;
    boolean notDirty = activeContent == null || !activeContent.isDirty();

    saveButton.setEnabled(!noDoc && !notDirty);
    saveAsButton.setEnabled(!noDoc);
    importButton.setEnabled(!noDoc);
    restoreButton.setEnabled(!noDoc);
    deleteButton.setEnabled(!noSelection);
    exportButton.setEnabled(!noSelection);
  }

  private void updateFrameTitle()
  {
    if(activeContent == null || !activeContent.hasDocument())
    {
      setTitle("证书库管理器");
    }
    else
    {
      TrustStoreDocument doc = activeContent.getDocument();
      setTitle(doc.getDisplayName() + (doc.isDirty() ? " *" : "") + " — 证书库管理器");
    }
  }

  private void updatePathLabel()
  {
    if(activeContent == null || !activeContent.hasDocument())
    {
      pathLabel.setText("未加载信任库");
    }
    else
    {
      TrustStoreDocument doc = activeContent.getDocument();
      pathLabel.setText(doc.getPath() == null ? "未保存的信任库" : doc.getPath().toString());
    }
  }

  private void syncStatus()
  {
    if(activeContent != null)
    {
      String text = activeContent.getStatusText();
      if(text != null && !text.isEmpty())
      {
        statusLabel.setText(text);
      }
    }
  }

  private void updateTabTitle(int idx, KeystoreTabContent content)
  {
    if(idx >= 0 && idx < tabPane.getTabCount())
    {
      tabPane.setTitleAt(idx, content.getTabTitle());
    }
  }

  private void handleCloseRequest()
  {
    for(int i = 0; i < tabPane.getTabCount(); i++)
    {
      KeystoreTabContent content = getContentAt(i);
      if(content != null && !content.checkUnsavedChanges())
      {
        return;
      }
    }
    saveSession();
    dispose();
    System.exit(0);
  }

  private void saveSession()
  {
    List<Path> openPaths = new ArrayList<>();
    for(int i = 0; i < tabPane.getTabCount(); i++)
    {
      KeystoreTabContent content = getContentAt(i);
      if(content != null)
      {
        TrustStoreDocument doc = content.getDocument();
        if(doc != null && doc.getPath() != null)
        {
          openPaths.add(doc.getPath());
          sessionService.savePassword(doc.getPath(), doc.getPassword());
        }
      }
    }
    sessionService.saveOpenFiles(openPaths);
  }

  private KeystoreTabContent getContentAt(int index)
  {
    if(index < 0 || index >= tabPane.getTabCount())
    {
      return null;
    }
    Component comp = tabPane.getComponentAt(index);
    if(comp instanceof JComponent jcomp)
    {
      Object obj = jcomp.getClientProperty("keystoreTabContent");
      if(obj instanceof KeystoreTabContent ktc)
      {
        return ktc;
      }
    }
    return null;
  }

  private int indexOfContent(KeystoreTabContent content)
  {
    if(content == null)
    {
      return -1;
    }
    for(int i = 0; i < tabPane.getTabCount(); i++)
    {
      if(getContentAt(i) == content)
      {
        return i;
      }
    }
    return -1;
  }

  private void status(String message)
  {
    statusLabel.setText(message);
  }
}
