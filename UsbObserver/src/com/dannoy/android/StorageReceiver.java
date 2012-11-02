package com.dannoy.android;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

public class StorageReceiver  extends BroadcastReceiver {
	String TAG = "StorageReceiver";
	  @Override
	  public void onReceive(Context context, Intent intent) {
		  //text_view.setText(intent.toString());
		  Log.v(TAG, "abcd " + intent.toString());
	  }
} 
