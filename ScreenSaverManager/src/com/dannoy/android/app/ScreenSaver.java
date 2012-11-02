package com.dannoy.android.app;

import android.app.Activity;
import android.app.WallpaperManager;
import android.service.wallpaper.IWallpaperConnection;
import android.service.wallpaper.IWallpaperService;
import android.service.wallpaper.IWallpaperEngine;
import android.service.wallpaper.WallpaperService;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;
import android.os.RemoteException;
import android.util.Log;
import android.view.View;
import android.view.WindowManager;

public class ScreenSaver extends Activity {
	private static final String TAG = "ScreenSaver";
	private WallpaperManager mWallpaperManager;
    private WallpaperConnection mWallpaperConnection;
    private Intent mWallpaperIntent;
    private View mView;
	
    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN);
        setContentView(R.layout.screensaver);
        
        BroadcastReceiver mMasterResetReciever = new BroadcastReceiver() {  
			public void onReceive(Context context, Intent intent) {  
                finish();  
				Log.i(TAG,"INFO: BroadcastReceiver");   
			}  
		};  
		registerReceiver(mMasterResetReciever, new IntentFilter(  
				Intent.ACTION_SCREEN_ON));
		
        mView = findViewById(R.id.configure); 
        mView.setVisibility(View.INVISIBLE);
		
		mWallpaperManager = WallpaperManager.getInstance(this);
		mWallpaperIntent = new Intent(WallpaperService.SERVICE_INTERFACE);
		mWallpaperIntent.setClassName("com.android.phasebeam", "com.android.phasebeam.PhaseBeamWallpaper");
        mWallpaperConnection = new WallpaperConnection(mWallpaperIntent);

        Log.i(TAG,"in onCreate");   
    }
    
    @Override
    public void onResume() {
        super.onResume();
        if (mWallpaperConnection != null && mWallpaperConnection.mEngine != null) {
            try {
                mWallpaperConnection.mEngine.setVisibility(true);
            } catch (RemoteException e) {
                // Ignore
            }
        }
    }
    
    @Override
    public void onPause() {
        super.onPause();
        if (mWallpaperConnection != null && mWallpaperConnection.mEngine != null) {
            try {
                mWallpaperConnection.mEngine.setVisibility(false);
            } catch (RemoteException e) {
                // Ignore
            }
        }
    }
    
    @Override
    public void onAttachedToWindow() {
        super.onAttachedToWindow();

        mView.post(new Runnable() {
            public void run() {
                if (!mWallpaperConnection.connect()) {
                    mWallpaperConnection = null;
                }
            }
        });
    }
    
    
    class WallpaperConnection extends IWallpaperConnection.Stub implements ServiceConnection {
        final Intent mIntent;
        IWallpaperService mService;
        IWallpaperEngine mEngine;
        boolean mConnected;
        private static final String LOG_TAG = "ScreenSaver.WallpaperConnection";

        WallpaperConnection(Intent intent) {
            mIntent = intent;
        }

        public boolean connect() {
            synchronized (this) {
                if (!bindService(mIntent, this, Context.BIND_AUTO_CREATE)) {
                    return false;
                }
                
                mConnected = true;
                return true;
            }
        }
        
        public void disconnect() {
            synchronized (this) {
                mConnected = false;
                if (mEngine != null) {
                    try {
                        mEngine.destroy();
                    } catch (RemoteException e) {
                        // Ignore
                    }
                    mEngine = null;
                }
                unbindService(this);
                mService = null;
            }
        }
        
        public void onServiceConnected(ComponentName name, IBinder service) {
            if (mWallpaperConnection == this) {
                mService = IWallpaperService.Stub.asInterface(service);
                try {
                    final View view = mView;
                    final View root = view.getRootView();
                    mService.attach(this, view.getWindowToken(),
                            WindowManager.LayoutParams.TYPE_APPLICATION_MEDIA_OVERLAY,
                            true, root.getWidth(), root.getHeight());
                } catch (RemoteException e) {
                    Log.w(LOG_TAG, "Failed attaching wallpaper; clearing", e);
                }
            }
        }

        public void onServiceDisconnected(ComponentName name) {
            mService = null;
            mEngine = null;
            if (mWallpaperConnection == this) {
                Log.w(LOG_TAG, "Wallpaper service gone: " + name);
            }
        }
        
        public void attachEngine(IWallpaperEngine engine) {
            synchronized (this) {
                if (mConnected) {
                    mEngine = engine;
                    try {
                        engine.setVisibility(true);
                    } catch (RemoteException e) {
                        // Ignore
                    }
                } else {
                    try {
                        engine.destroy();
                    } catch (RemoteException e) {
                        // Ignore
                    }
                }
            }
        }
        
        public ParcelFileDescriptor setWallpaper(String name) {
            return null;
        }
    }
}
