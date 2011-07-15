/*  SpoofingActivity.java is the activity that is shown while spoofing
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

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;

import android.app.Activity;
import android.net.wifi.WifiManager;
import android.os.Bundle;
import android.text.format.Formatter;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.CompoundButton.OnCheckedChangeListener;
import android.widget.ListView;
import android.widget.TextView;
import android.content.Context;
import android.content.Intent;

public class SpoofingActivity extends Activity {
	private static final String TAG = "SpoofingActivity";
	private Bundle mBundle;
	protected static volatile boolean isSpoofing = false;
	private final String IPV4_FILEPATH = "/proc/sys/net/ipv4/ip_forward";
	private final String IPV6_FILEPATH = "/proc/sys/net/ipv6/conf/all/forwarding";
	private static ExecuteCommand tcpdumpCmd;


	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.spoofing);
		mBundle = getIntent().getExtras();
		final TextView target_tv = (TextView) findViewById(R.id.targetText);
		target_tv.append(mBundle.getString("gateway"));

		//ipv4 checkbox
		final CheckBox ipv4_cb = (CheckBox) findViewById(R.id.forward_ipv4);
		try {
			ipv4_cb.setChecked(isForwarding(IPV4_FILEPATH));
		} catch (FileNotFoundException e) {
			Log.w(TAG, "couldn't find network forwarding file", e);
			ipv4_cb.setEnabled(false);
		}
		ipv4_cb.setOnCheckedChangeListener(new OnCheckedChangeListener() {
			public void onCheckedChanged(CompoundButton bv, boolean checked) {
				try {
					if(checked) {
						ExecuteCommand ec = new ExecuteCommand("echo 1 > " + IPV4_FILEPATH);
						ec.start();
					} else {
						ExecuteCommand ec = new ExecuteCommand("echo 0 > " + IPV4_FILEPATH);
						ec.start();
					}
				} catch (IOException e) {
					Log.e(TAG, "error when changing ipv4 forwarding", e);
				}
			}
		});

		//ipv6 checkbox
		final CheckBox ipv6_cb = (CheckBox) findViewById(R.id.forward_ipv6);
		try {
			ipv6_cb.setChecked(isForwarding(IPV6_FILEPATH));
		} catch (FileNotFoundException e) {
			Log.w(TAG, "couldn't find network forwarding file", e);
			ipv6_cb.setEnabled(false);
		}
		ipv6_cb.setOnCheckedChangeListener(new OnCheckedChangeListener() {
			public void onCheckedChanged(CompoundButton bv, boolean checked) {
				try {
					if(checked) {
						ExecuteCommand ec = new ExecuteCommand("echo 1 > " + IPV6_FILEPATH);
						ec.start();
					} else {
						ExecuteCommand ec = new ExecuteCommand("echo 0 > " + IPV6_FILEPATH);
						ec.start();
					}
				} catch (IOException e) {
					Log.e(TAG, "error when changing ipv6 forwarding", e);
				}
			}
		});

		final Button stopButton = (Button) findViewById(R.id.stop);
		stopButton.setOnClickListener(new OnClickListener() {
			public void onClick(View v) {
				Intent intent = new Intent(v.getContext(), ArpspoofService.class);
				stopService(intent);
				stopTcpdump();
				finish();
			}
		});        
	}

	@Override
	protected void onStart() {
		super.onStart();
		if(!isSpoofing) {
			Intent intent = new Intent(this, ArpspoofService.class);
			intent.putExtras(mBundle);
			startService(intent);
			isSpoofing = true;
			startTcpdump();
		}
	}

	private void startTcpdump() {
		final ListView outputLV = (ListView) findViewById(R.id.OutputLV);
		WifiManager wManager = (WifiManager) getSystemService(Context.WIFI_SERVICE);
		String localhost = Formatter.formatIpAddress(wManager.getConnectionInfo().getIpAddress());
		ArrayAdapter<String> outputAdapter = new ArrayAdapter<String>(this, R.layout.list_item);
		outputLV.setAdapter(outputAdapter);
		try {
			tcpdumpCmd = new ExecuteCommand(getFileStreamPath(Arpspoof.TCPDUMP).toString() + " not '(src host "
					+ localhost + " or dst host " + localhost + " or arp)'", outputLV, outputAdapter);
		} catch (IOException e) {
			Log.e(TAG, "error running tcpdump", e);
		}
		tcpdumpCmd.start();
	}

	private void stopTcpdump() {
		if(tcpdumpCmd != null) {
			tcpdumpCmd.interrupt();
			tcpdumpCmd = null;
			try {
				ExecuteCommand ec = new ExecuteCommand("killall " + Arpspoof.TCPDUMP);
				ec.start();
				ec.join();
			} catch (IOException e) {
				Log.e(TAG, "error killing tcpdump", e);
			} catch (InterruptedException e) {
				// swallow error
			}
		}
	}
	
	private boolean isForwarding(String filePath) throws FileNotFoundException {
		boolean forwarding = false;
		BufferedReader br;
		try {
			br = new BufferedReader(new FileReader(filePath));
			char[] buff = new char[2];
			br.read(buff, 0, 1);
			if(buff[0] == '1')
				forwarding = true;
			br.close();
		} catch (IOException e) {
			Log.w(TAG, "error reading forwarding file", e);
		}
		return forwarding;
	}

}
