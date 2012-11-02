package com.dannoy.android;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.storage.StorageEventListener;
import android.os.storage.StorageManager;
import android.util.Log;
import android.widget.TextView;

public class UsbObserverActivity extends Activity {
	String TAG = "UsbObserverActivity";
	TextView text_view;
	StorageManager mStorageManager;
	
	private final StorageEventListener mStorageListener = new StorageEventListener()
    {
        @Override
        public void onStorageStateChanged(String path, String oldState, String newState)
        {
            String text = "";
            text += "state changed notification that " + path + " changed state from " + oldState + " to " + newState;
            //mText.setText(text);
            text_view.setText(text);
            Log.v(TAG, "abcde " + text);
        }
    };

    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        
        text_view = (TextView) findViewById(R.id.text_view);
        mStorageManager = (StorageManager) getSystemService(Context.STORAGE_SERVICE);
        mStorageManager.registerListener(mStorageListener); 
    }
    
    
}
