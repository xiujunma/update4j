/*
 * Copyright 2018 Mordechai Meisels
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * 
 * 		http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.update4j.util;

import org.update4j.OS;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.file.*;
import java.security.*;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.zip.Adler32;
import java.util.zip.ZipFile;

import static java.util.Arrays.asList;

public class FileUtils {

	private FileUtils() {
	}

	public static long getChecksum(Path path) throws IOException {
		try (InputStream input = Files.newInputStream(path)) {
			Adler32 checksum = new Adler32();
			byte[] buf = new byte[1024 * 8];

			int read;
			while ((read = input.read(buf, 0, buf.length)) > -1)
				checksum.update(buf, 0, read);

			return checksum.getValue();
		}
	}

	public static String getChecksumString(Path path) throws IOException {
		return Long.toHexString(getChecksum(path));
	}

	public static boolean isJarFile(Path path) throws IOException {
		if (!isZipFile(path)) {
			return false;
		}

		try (ZipFile zip = new ZipFile(path.toFile())) {
			return zip.getEntry("META-INF/MANIFEST.MF") != null;
		}
	}

	public static boolean isZipFile(Path path) throws IOException {
		if (Files.isDirectory(path)) {
			return false;
		}
		if (!Files.isReadable(path)) {
			throw new IOException("Cannot read file " + path.toAbsolutePath());
		}
		if (Files.size(path) < 4) {
			return false;
		}

		try (DataInputStream in = new DataInputStream(Files.newInputStream(path))) {
			int test = in.readInt();
			return test == 0x504b0304;
		}
	}

	public static byte[] sign(Path path, PrivateKey key) throws IOException {
		try {
			Signature sign = Signature.getInstance("SHA256with" + key.getAlgorithm());
			sign.initSign(key);

			try (InputStream input = Files.newInputStream(path)) {
				byte[] buf = new byte[1024 * 8];
				int len;
				while ((len = input.read(buf, 0, buf.length)) > 0)
					sign.update(buf, 0, len);
			}

			return sign.sign();
		} catch (InvalidKeyException | SignatureException e) {
			throw new IOException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new AssertionError(e);
		}
	}

	public static String signAndEncode(Path path, PrivateKey key) throws IOException {
		return Base64.getEncoder().encodeToString(sign(path, key));
	}

	public static Path fromUri(URI uri) {
		String path = uri.getPath();

		if (uri.isAbsolute()) {
			path = path.substring(path.lastIndexOf("/") + 1);
		}

		return Paths.get(path);

	}

	public static URI fromPath(Path path) {
		if (path.isAbsolute()) {
			Path filename = path.getFileName();

			return fromPath(filename);
		}

		try {
			String uri = URLEncoder.encode(path.toString().replace("\\", "/"), "UTF-8");

			uri = uri.replace("%2F", "/") // We still need directory structure
							.replace("+", "%20"); // "+" only means space in queries, not in paths
			return URI.create(uri);
		} catch (UnsupportedEncodingException e) {
			throw new AssertionError(e);
		}

	}

	public static URI relativize(URI base, URI other) {
		if (base == null || other == null)
			return other;

		return base.relativize(other);
	}

	public static Path relativize(Path base, Path other) {
		if (base == null || other == null)
			return other;

		try {
			return base.relativize(other);
		} catch (IllegalArgumentException e) {
		}

		return other;
	}

	public static OS fromFilename(String filename) {
		Pattern osPattern = Pattern.compile(".+-(linux|win|mac)\\.[^.]+");
		Matcher osMatcher = osPattern.matcher(filename);

		if (osMatcher.matches()) {
			return OS.fromShortName(osMatcher.group(1));
		}

		return null;
	}

	public static boolean isEmptyDirectory(Path path) throws IOException {
		if (Files.isDirectory(path)) {
			try (DirectoryStream<Path> dir = Files.newDirectoryStream(path)) {
				return !dir.iterator().hasNext();
			}
		}

		return false;
	}

	public static void windowsHide(Path file) {
		if (OS.CURRENT != OS.WINDOWS)
			return;

		try {
			Files.setAttribute(file, "dos:hidden", true);
		} catch (Exception e) {
		}
	}

	public static void windowsUnhide(Path file) {
		if (OS.CURRENT != OS.WINDOWS)
			return;

		try {
			Files.setAttribute(file, "dos:hidden", false);
		} catch (Exception e) {
		}
	}

	public static void verifyNotLocked(Path path) throws IOException {
		if (OS.CURRENT != OS.WINDOWS)
			return;

		if (!Files.isRegularFile(path)) {
			return;
		}

		Path temp = Files.createTempFile(path.getParent(), null, null);

		try {
			Files.move(path, temp, StandardCopyOption.REPLACE_EXISTING);
			Files.move(temp, path);
		} finally {
			Files.deleteIfExists(temp);
		}

	}

	public static void secureMoveFile(Path source, Path target) throws IOException {
		if (OS.CURRENT == OS.WINDOWS || Files.notExists(target)) {
			Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
			return;
		}

		// At this point we are on non-windows and exists
		// Lets unlink file first so we don't run into file-busy errors.
		Path temp = Files.createTempFile(target.getParent(), null, null);
		Files.move(target, temp, StandardCopyOption.REPLACE_EXISTING);

		try {
			Files.move(source, target);
		} catch (IOException e) {
			Files.move(temp, target);
			throw e;
		} finally {
			Files.deleteIfExists(temp);
		}
	}

	public static void delayedDelete(Collection<Path> files, int secondsDelay) {
		secondsDelay = Math.max(secondsDelay, 1);
		List<String> commands = new ArrayList<>();

		String filenames = files.stream()
						.map(Path::toString)
						.map(f -> "\"" + f.replace("\"", "\\\"") + "\"")
						.collect(Collectors.joining(" "));

		if (OS.CURRENT == OS.WINDOWS) {
			commands.addAll(asList("cmd", "/c"));
			commands.add("ping localhost -n " + (secondsDelay + 1) + " & del " + filenames);
		} else {
			commands.addAll(asList("sh", "-c"));
			commands.add("sleep " + secondsDelay + " ; rm " + filenames);
		}

		ProcessBuilder pb = new ProcessBuilder(commands);

		Runtime.getRuntime().addShutdownHook(new Thread(() -> {
			try {
				pb.start();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}));
	}
}
