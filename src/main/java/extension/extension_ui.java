package extension;

import target_web_app.web_request;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import burp.api.montoya.MontoyaApi;


public class extension_ui
{
    private JTextField url_field;
    private JCheckBox SQLiCheckBox;
    private JCheckBox XSSCheckBox;
    private JCheckBox pathTraversalCheckBox;
    private JButton scanButton;
    private JPanel user_interface;
    private JTextArea output;
    private static extension_ui ui_instance = null;

    private extension_ui(MontoyaApi api)
    {
        scanButton.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent actionEvent)
            {
                /*
                * scan all vulns checked on the checkboxes using threads
                * */
            }
        });
    }

    protected static JPanel getUser_interface(MontoyaApi api)
    {
        if (ui_instance == null) ui_instance = new extension_ui(api);
        return ui_instance.user_interface;
    }


}
