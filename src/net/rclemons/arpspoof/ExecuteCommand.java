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

class ExecuteCommand extends Thread
{
	private static final String TAG = "ExecuteCommand";
	private final String command;
	private final Process process;
	private final BufferedReader reader;
	private final BufferedReader errorReader;
	private final DataOutputStream os;

	public ExecuteCommand(String cmd) throws IOException {
		command = cmd;
		process = Runtime.getRuntime().exec("su");
		reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
		errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
		os = new DataOutputStream(process.getOutputStream());
	}

	public void run() {

		class StreamGobler extends Thread {
			/*"gobblers" seem to be the recommended way to ensure the streams don't cause issues */

			public BufferedReader buffReader;

			public StreamGobler(BufferedReader br) {
				buffReader = br;

			}

			public void run() {
				char[] buffer = new char[4096];
				try {
					while (buffReader.read(buffer) > 0) {
						/* TODO log stream */
					}
				} catch (IOException e) {
					Log.w(TAG, "StreamGobbler couldn't read stream", e);
				} finally {
					try {
						buffReader.close();
					} catch (IOException e) {
						//swallow error
					}
				}
			}
		}

		try {
			os.writeBytes(command + '\n');
			os.flush();
			StreamGobler errorGobler = new StreamGobler(errorReader);
			StreamGobler stdOutGobbler = new StreamGobler(reader);
			errorGobler.setDaemon(true);
			stdOutGobbler.setDaemon(true);
			errorGobler.start();
			stdOutGobbler.start();
			os.writeBytes("exit\n");
			os.flush();
			//The following catastrophe of code seems to be the best way to ensure this thread can be interrupted
			while(!Thread.currentThread().isInterrupted()) {
				try {
					process.exitValue();
					Thread.currentThread().interrupt();
				} catch (IllegalThreadStateException e) {
					//just sleep, the process hasn't terminated yet but sleep should(but doesn't) cause InterruptedException to be thrown if interrupt() has been called
					Thread.sleep(250);//.25 seconds seems reasonable
				}
			}
		} catch (IOException e) {
			Log.e(TAG, "error running commands", e);
		} catch (InterruptedException e) {
			try {
				os.close();//key to killing executable and process
				reader.close();
				errorReader.close();
			} catch (IOException ex) {
				// swallow error
			} finally {
				process.destroy();
			}
		} finally {
			process.destroy();
		}
	}

}