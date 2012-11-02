package com.dannoy.android.app;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;

public class ScreenSaverManagerActivity extends Activity {
    private static final String TAG = "ScreenSaverManagerActivity";

    /** Called when the activity is first created. */
    @Override
        public void onCreate(Bundle savedInstanceState) {
            super.onCreate(savedInstanceState);
            setContentView(R.layout.main);
            Log.i(TAG,"in onCreate");  
            Intent mService=new Intent(ScreenSaverManagerActivity.this,ScreenSaverService.class);//启动服务  
            mService.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);  
            startService(mService);  
        }
}
