package org.qubership.cloud.dbaas.watcher;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.WatchService;

public class FileChangeWatcher {
	public FileChangeWatcher() throws IOException {
		WatchService watchService = FileSystems.getDefault().newWatchService();
	}
}
