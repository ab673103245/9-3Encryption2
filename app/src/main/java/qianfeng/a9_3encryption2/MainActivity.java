package qianfeng.a9_3encryption2;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.TextView;

public class MainActivity extends AppCompatActivity {

    private TextView tv;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        tv = ((TextView) findViewById(R.id.tv));
    }

    public void desEncode(View view) { // des解密
        String des = EncryptionHelper.des("hello world!", "123456999999999999998888", EncryptionHelper.ENCODE);
        tv.setText(des);
    }

    public void desDecode(View view) { // des加密
        String des = EncryptionHelper.des(tv.getText().toString(), "123456999999999999998888", EncryptionHelper.DECODE);
        tv.setText(des);
    }

    public void des3Encode(View view) {
        String des = EncryptionHelper.des3("hello world!", "123456999999999999998888", EncryptionHelper.ENCODE);
        tv.setText(des);
    }

    public void des3Decode(View view) {
        String des = EncryptionHelper.des3(tv.getText().toString(), "123456999999999999998888", EncryptionHelper.DECODE);
        tv.setText(des);
    }

    public void aesEncode(View view) {
        String des = EncryptionHelper.aes("hello world!", "123456999999999999998888", EncryptionHelper.ENCODE);
        tv.setText(des);
    }

    public void aesDecode(View view) {
        String des = EncryptionHelper.aes(tv.getText().toString(), "123456999999999999998888", EncryptionHelper.DECODE);
        tv.setText(des);
    }

    public void rsaEncode(View view) {
        String s = EncryptionHelper.rsaEncode("hello world!");
        tv.setText(s);
    }

    public void rsaDecode(View view) {
        String s = EncryptionHelper.rsaDecode(tv.getText().toString());
        tv.setText(s);
    }
}
