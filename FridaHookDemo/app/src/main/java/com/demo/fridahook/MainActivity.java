package com.demo.fridahook;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;

public class MainActivity extends AppCompatActivity {

    static {
        System.loadLibrary("native-lib");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Button display = (Button)findViewById(R.id.button);

        display.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                HookClass hookClass = new HookClass(100, "HookClass");
                hookClass.display();
            }
        });
    }
}



