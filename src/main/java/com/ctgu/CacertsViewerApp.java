package com.ctgu;

import com.ctgu.ui.MainWindow;
import com.formdev.flatlaf.FlatLightLaf;

import javax.swing.*;

public class CacertsViewerApp
{
  public static void main(String[] args)
  {
    SwingUtilities.invokeLater(() -> {
      try
      {
        FlatLightLaf.setup();
        UIManager.put("TabbedPane.showTabSeparators", true);
        UIManager.put("Table.showHorizontalLines", true);
        UIManager.put("Table.showVerticalLines", true);
      }
      catch(Exception e)
      {
        try
        {
          UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        }
        catch(Exception ignored)
        {
        }
      }
      MainWindow window = new MainWindow();
      window.setVisible(true);
      window.onShown();
    });
  }
}
