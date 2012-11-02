package com.dannoy.android.app;

import android.app.KeyguardManager;
import android.app.KeyguardManager.KeyguardLock;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.IBinder;
import android.util.Log;

public class ScreenSaverService extends Service{
	private static final String TAG = "ScreenSaverService";
	KeyguardManager mKeyguardManager = null;  
	private KeyguardLock mKeyguardLock = null;  
	@Override  
	public IBinder onBind(Intent arg0) {  
		// TODO Auto-generated method stub  
		return null;  
	}  
	@Override  
	public void onCreate()  
	{  
		// TODO Auto-generated method stub  
		Log.i(TAG,"in Service onCreate"); 
		super.onCreate();  
	}  
	@Override  
	public void onStart(Intent intent, int startId)  
	{  
		// TODO Auto-generated method stub  
		Log.i(TAG,"in Service");  
		mKeyguardManager = (KeyguardManager) getSystemService(Context.KEYGUARD_SERVICE);  
		mKeyguardLock = mKeyguardManager.newKeyguardLock("");  
		mKeyguardLock.disableKeyguard();   
		BroadcastReceiver mMasterResetReciever = new BroadcastReceiver() {  
			public void onReceive(Context context, Intent intent) {  
				try {  
					Intent i = new Intent();  
					i.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);  
					i.setClass(context, ScreenSaver.class);  
					context.startActivity(i); 
					// finish();  
					Log.i(TAG,"INFO: BroadcastReceiver");  
				} catch (Exception e) {  
					Log.i(TAG, "ERROR: " + e.toString());  
				}  
			}  
		};  
		registerReceiver(mMasterResetReciever, new IntentFilter(  
				Intent.ACTION_SCREEN_OFF));  
	}  

}
