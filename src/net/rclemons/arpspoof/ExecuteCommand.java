/*  ExecuteCommand.java uses java's exec to execute commands as root
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
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;

import android.util.Log;
import android.widget.ArrayAdapter;
import android.widget.ListView;

class ExecuteCommand extends Thread
{
	private static final String TAG = "ExecuteCommand";
	private final String command;
	private Process process = null;
	private BufferedReader reader = null;
	private BufferedReader errorReader = null;
	private DataOutputStream os = null;
	private ListView outputLV = null;
	private ArrayAdapter<String> outputAdapter = null;
	private static final int NUM_ITEMS = 5;


	public ExecuteCommand(String cmd) throws IOException {
		command = cmd;
		process = Runtime.getRuntime().exec("su");
		reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
		errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
		os = new DataOutputStream(process.getOutputStream());
	}
	
	public ExecuteCommand(String cmd, ListView lv, ArrayAdapter<String> aa) throws IOException {
		this(cmd);
		outputLV = lv;
		outputAdapter = aa;
	}

	public void run() {

		class StreamGobbler extends Thread {
			/*"gobblers" seem to be the recommended way to ensure the streams don't cause issues */

			public BufferedReader buffReader = null;

			public StreamGobbler(BufferedReader br) {
				buffReader = br;

			}

			public void run() {
				try {
					String line = null;
					if(outputLV == null) {
						 char[] buffer = new char[4096];
						 while (buffReader.read(buffer) > 0) {
						 }
					}
					else {
						while ((line = buffReader.readLine()) != null) {
							if(outputLV != null) {
								final String tmpLine = new String(line);
								outputLV.post(new Runnable() {
									public void run() {
										outputAdapter.add(tmpLine);
										if(outputAdapter.getCount() > NUM_ITEMS)
											outputAdapter.remove(outputAdapter.getItem(0));
									}
								});
							}
						}
					}
				} catch (IOException e) {
					Log.w(TAG, "StreamGobbler couldn't read stream", e);
				} finally {
					try {
						if(buffReader != null) {
							buffReader.close();
							buffReader = null;
						}
					} catch (IOException e) {
						//swallow error
					}
				}
			}
		}

		try {
			os.writeBytes(command + '\n');
			os.flush();
			StreamGobbler errorGobbler = new StreamGobbler(errorReader);
			StreamGobbler stdOutGobbler = new StreamGobbler(reader);
			errorGobbler.setDaemon(true);
			stdOutGobbler.setDaemon(true);
			errorGobbler.start();
			stdOutGobbler.start();
			os.writeBytes("exit\n");
			os.flush();
			//The following catastrophe of code seems to be the best way to ensure this thread can be interrupted
			while(!Thread.currentThread().isInterrupted()) {
				try {
					process.exitValue();
					Thread.currentThread().interrupt();
				} catch (IllegalThreadStateException e) {
					//the process hasn't terminated yet so sleep some, then check again
					Thread.sleep(250);//.25 seconds seems reasonable
				}
			}
		} catch (IOException e) {
			Log.e(TAG, "error running commands", e);
		} catch (InterruptedException e) {
			try {
				if(os != null) {
					os.close();//key to killing executable and process
					os = null;
				}
				if(reader != null) {
					reader.close();
					reader = null;
				}
				if(errorReader != null) {
					errorReader.close();
					errorReader = null;
				}
			} catch (IOException ex) {
				// swallow error
			} finally {
				if(process != null) {
					process.destroy();
					process = null;
				}
			}
		} finally {
			if(process != null) {
				process.destroy();
				process = null;
			}
		}
	}

}