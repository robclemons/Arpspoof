/*    ArpspoofService.java implements the background service that controls running the native binary
    Copyright (C) 2011 Robbie Clemons <robclemons@gmail.com>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA. */

package net.rclemons.arpspoof;

import java.io.IOException;

import android.app.IntentService;
import android.app.Notification;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.PowerManager;
import android.net.wifi.WifiManager;
import android.util.Log;

public class ArpspoofService extends IntentService {
	
	private static final String TAG = "ArpspoofService";
	private static final int SHOW_SPOOFING = 1;
	private volatile Thread myThread;
	private static volatile WifiManager.WifiLock wifiLock;
	private static volatile PowerManager.WakeLock wakeLock;
	protected static volatile boolean isSpoofing = false;
	
	public ArpspoofService() {
		super("ArpspoofService");
	}
	
	@Override
	public void onHandleIntent(Intent intent) {
		Bundle bundle = intent.getExtras();
		String localBin = bundle.getString("localBin");
		String gateway = bundle.getString("gateway");
		String wifiInterface = bundle.getString("interface");
		final String command = localBin + " -i " + wifiInterface + " " + gateway;
		Notification notification = new Notification(R.drawable.ic_stat_spoofing, "now spoofing: " + gateway, System.currentTimeMillis());
		Intent launchActivity = new Intent(this, SpoofingActivity.class);
		launchActivity.putExtras(bundle);
		PendingIntent pendingIntent = PendingIntent.getActivity(this, 0, launchActivity, 0);
		notification.setLatestEventInfo(this, "spoofing: " + gateway,
				"tap to open Arpspoof", pendingIntent);
		startForeground(SHOW_SPOOFING, notification);
		PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
		WifiManager wm = (WifiManager) getSystemService(Context.WIFI_SERVICE);
		wifiLock = wm.createWifiLock(WifiManager.WIFI_MODE_FULL, "wifiLock");
		wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "wakeLock");
		wifiLock.acquire();
		wakeLock.acquire();
		try {
			myThread = new ExecuteCommand(command);
		} catch (IOException e) {
			Log.e(TAG, "error initializing arpspoof command", e);
		}
		myThread.setDaemon(true);
		isSpoofing = true;
		myThread.start();
		try {
			myThread.join();
		} catch (InterruptedException e) {
			Log.i(TAG, "Spoofing was interrupted", e);
		}
		if(myThread != null)
			myThread = null;
	}

	@Override
	public void onDestroy() {
		Thread killAll;
		try {
			killAll = new ExecuteCommand("killall arpspoof");
			killAll.setDaemon(true);
			killAll.start();
			killAll.join();
		} catch (IOException e) {
			Log.w(TAG, "error initializing killall arpspoof command", e);
		} catch (InterruptedException e) {
			// don't care
		}
		
		if(myThread != null) {
			myThread.interrupt();
			myThread = null;
		}
		wifiLock.release();
		wakeLock.release();
		stopForeground(true);
		isSpoofing = false;
	}
}