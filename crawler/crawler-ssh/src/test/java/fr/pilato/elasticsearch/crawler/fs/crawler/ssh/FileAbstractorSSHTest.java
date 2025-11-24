/*
 * Licensed to David Pilato (the "Author") under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. Author licenses this
 * file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package fr.pilato.elasticsearch.crawler.fs.crawler.ssh;
import fr.pilato.elasticsearch.crawler.fs.framework.OsValidator;

import fr.pilato.elasticsearch.crawler.fs.crawler.FileAbstractModel;
import fr.pilato.elasticsearch.crawler.fs.crawler.FileAbstractor;
import fr.pilato.elasticsearch.crawler.fs.settings.FsSettings;
import fr.pilato.elasticsearch.crawler.fs.settings.FsSettingsLoader;
import fr.pilato.elasticsearch.crawler.fs.test.framework.AbstractFSCrawlerTestCase;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.sshd.common.config.keys.writer.openssh.OpenSSHKeyPairResourceWriter;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.config.keys.AuthorizedKeysAuthenticator;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.common.file.virtualfs.VirtualFileSystemFactory;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.server.SftpFileSystemAccessor;
import org.apache.sshd.sftp.server.SftpSubsystemFactory;
import org.apache.sshd.sftp.server.SftpSubsystemProxy;
import org.assertj.core.groups.Tuple;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.ArrayList;
import java.util.Collections;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

/**
 * This is an integration test for the SSH File Abstractor.
 * It verifies that the crawler can correctly connect to an SSH server, list files
 * and directories, and accurately interpret their attributes.
 * It works by starting an embedded mock SSH server that serves a temporary,
 * fake filesystem created on the local machine.
 */
public class FileAbstractorSSHTest extends AbstractFSCrawlerTestCase {
    private static final Logger logger = LogManager.getLogger();
    private static final String SSH_USERNAME = "USERNAME";
    private static final String SSH_PASSWORD = "PASSWORD";
    private SshServer sshd = null;
    Path testDir = rootTmpDir.resolve("test-ssh");

    /**
     * Sets up a complete, temporary SSH environment before each test.
     * This includes creating a fake filesystem and starting a mock SSH server.
     */
    @Before
    public void setup() throws IOException, NoSuchAlgorithmException {
        if (Files.notExists(testDir)) {
            Files.createDirectory(testDir);
        }

        // Create a predictable, temporary filesystem for the mock SSH server to use.
        // Add some fake files to the test-ssh directory
        /*
        /testfile.txt
        /nested
            /foo.txt
            /bar.txt
            /buzz
                /hello.txt
                /world.txt
        /permission
            /all.txt (with all permissions)
            /none.txt (with no permissions)
        /subdir_with_space
            /hello.txt
            /world.txt
         */

        // Create /testfile.txt
        addFakeFile(testDir, "testfile.txt", "I'm a test file");

        // Create /nested
        addFakeDir(testDir, "nested");
        // Create /nested/foo.txt
        addFakeFile(testDir.resolve("nested"), "foo.txt", "文件名不支持中文");
        // Create /nested/bar.txt
        addFakeFile(testDir.resolve("nested"), "bar.txt", "bar file");

        // Create nested/buzz
        Path buzzDir = addFakeDir(testDir.resolve("nested"), "buzz");
        // Create /nested/buzz/hello.txt
        addFakeFile(buzzDir, "hello.txt", "hello");
        // Create /nested/buzz/world.txt
        addFakeFile(buzzDir, "world.txt", "world");

        // Create /permission
        Path permissionDir = addFakeDir(testDir, "permission");
        // Create /permission/all.txt with all permissions
        // We explicitly set these permissions to test that the crawler can correctly
        // read both permissive and restrictive file attributes.
        Path allFile = permissionDir.resolve("all.txt");
        if (Files.notExists(allFile)) {
            Files.writeString(allFile, "123");
        }
        allFile.toFile().setReadable(true, false);
        allFile.toFile().setWritable(true, false);
        allFile.toFile().setExecutable(true, false);
        // Create /permission/none.txt with no permissions
        Path noneFile = permissionDir.resolve("none.txt");
        if (Files.notExists(noneFile)) {
            Files.writeString(noneFile, "456");
        }
        noneFile.toFile().setReadable(false, false);
        noneFile.toFile().setWritable(false, false);
        noneFile.toFile().setExecutable(false, false);

        // Trailing spaces are not supported on Windows. So we are running this test only on non-windows platforms.
        if (!OsValidator.WINDOWS) {
            // Create "/subdir_with_space "
            Path subdirWithSpace = addFakeDir(testDir, "subdir_with_space ");
            // Create "/subdir_with_space /hello.txt"
            addFakeFile(subdirWithSpace, "hello.txt", "File in dir with space at the end");
            // Create "/subdir_with_space /world.txt"
            addFakeFile(subdirWithSpace, "world.txt", "File in dir with space at the end");
        }

        /*
        // Create "/chérie"
        Path dirWithUtf8InName = addFakeDir(testDir, "chérie");
        // Create "/chérie/hello.txt"
        addFakeFile(dirWithUtf8InName, "hello.txt", "hello");
        // Create "/chérie/world.txt"
        addFakeFile(dirWithUtf8InName, "world.txt", "world");
         */

        // Generate the key files for our SSH tests
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        saveKeyPair(rootTmpDir, keyPair);

        // Start an embedded SSH server on a random available port.
        sshd = SshServer.setUpDefaultServer();
        sshd.setHost("localhost");
        sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider(rootTmpDir.resolve("host.ser")));

        // Configure authentication: allow both password and public key (PEM) auth.
        sshd.setPasswordAuthenticator((username, password, session) ->
                SSH_USERNAME.equals(username) && SSH_PASSWORD.equals(password));
        sshd.setPublickeyAuthenticator(new AuthorizedKeysAuthenticator(rootTmpDir.resolve("public.key")));

        // Set up the SFTP subsystem.
        sshd.setSubsystemFactories(Collections.singletonList(new SftpSubsystemFactory()));

        // This is the most critical part of the setup. It tells the SSH server to use our temporary `testDir`
        // as its root directory. This "sandboxes" the test, ensuring it doesn't accidentally read from
        // the real filesystem (like C:\).
        sshd.setFileSystemFactory(new VirtualFileSystemFactory(testDir));
        sshd.start();

        logger.info(" -> Started fake SSHD service on {}:{}", sshd.getHost(), sshd.getPort());
    }

    /**
     * Saves a generated KeyPair into public and private key files that the SSH server and client can use.
     */
    private void saveKeyPair(Path path, KeyPair keyPair) {
        OpenSSHKeyPairResourceWriter writer = new OpenSSHKeyPairResourceWriter();

        // Store Public Key.
        try (FileOutputStream fos = new FileOutputStream(path.resolve("public.key").toFile())) {
            writer.writePublicKey(keyPair.getPublic(), "Public Key for tests", fos);
        } catch (GeneralSecurityException | IOException e) {
            logger.error("Failed to save public key", e);
        }

        // Store Private Key.
        try (FileOutputStream fos = new FileOutputStream(path.resolve("private.key").toFile())) {
            writer.writePrivateKey(keyPair, "Private Key for tests", null, fos);
        } catch (GeneralSecurityException | IOException e) {
            logger.error("Failed to save public key", e);
        }
    }

    /**
     * Cleanly shuts down the mock SSH server after each test.
     */
    /**
     * Cleanly shuts down the mock SSH server after each test.
     * The `stop(true)` call ensures an immediate shutdown.
     */
    @After
    public void shutDown() throws IOException {
        if (sshd != null) {
            sshd.stop(true);
            sshd.close();
            logger.info(" -> Stopped fake SSHD service on {}:{}", sshd.getHost(), sshd.getPort());
        }
    }

    /**
     * A basic "smoke test" to verify that the underlying SSH client can successfully connect
     * and authenticate to the mock server using both password and PEM key methods.
     */
    @Test
    public void sshClient() throws Exception {
        // Test with login / password
        try (FsCrawlerSshClient client = new FsCrawlerSshClient(SSH_USERNAME, SSH_PASSWORD, null,
                sshd.getHost(),sshd.getPort())) {
            client.open();
            SftpClient.Attributes stat = client.getSftpClient().stat("/");
            assertThat(stat.isDirectory()).isTrue();
        }

        // Test with PEM file
        try (FsCrawlerSshClient client = new FsCrawlerSshClient(SSH_USERNAME, null,
                rootTmpDir.resolve("private.key").toString(),
                sshd.getHost(),sshd.getPort())) {
            client.open();
            SftpClient.Attributes stat = client.getSftpClient().stat("/");
            assertThat(stat.isDirectory()).isTrue();
        }
    }

    /**
     * This is the core test method. It thoroughly tests the `FileAbstractorSSH` class
     * by connecting to the mock server and asserting the contents of the fake filesystem.
     */
    @Test
    public void fileAbstractorSSH() throws Exception {
        // Define OS-specific permission values. This is crucial for making the test stable across different
        // operating systems (like Windows and Linux) which report permissions differently.
        final int dirPerms = OsValidator.WINDOWS ? 16822 : 16877;
        final int filePerms = OsValidator.WINDOWS ? 33206 : 33188;
        final int allPerms = OsValidator.WINDOWS ? 33206 : 33279;
        final int nonePerms = OsValidator.WINDOWS ? 33060 : 32768;

        FsSettings fsSettings = FsSettingsLoader.load();
        fsSettings.getServer().setHostname(sshd.getHost());
        fsSettings.getServer().setPort(sshd.getPort());
        fsSettings.getServer().setUsername(SSH_USERNAME);
        fsSettings.getServer().setPassword(SSH_PASSWORD);

        // The test data is defined using AssertJ's `tuple`. The structure for these tuples is:
        // tuple(name, isDirectory, extension, path, fullpath, permissions, owner, group, size)
        // This structure must match the properties extracted in the testFilesInDir() helper method.

        // --- First run: Test with login/password ---
        try (FileAbstractor<?> fileAbstractor = new FileAbstractorSSH(fsSettings)) {
            fileAbstractor.open();
            assertThat(fileAbstractor.exists("/ThisPathDoesNotExist")).isFalse();

            testFilesInDir(fileAbstractor, "/ThisPathDoesNotExist");

            java.util.List<Tuple> rootDirTuples = new ArrayList<>();
            rootDirTuples.add(tuple("nested", true, "", "/", "/nested", dirPerms, "0", "0", 0L));
            rootDirTuples.add(tuple("permission", true, "", "/", "/permission", dirPerms, "0", "0", 0L));
            // This test case is skipped on Windows because its filesystem does not support
            // directory names with trailing spaces.
            if (!OsValidator.WINDOWS) {
                rootDirTuples.add(tuple("subdir_with_space ", true, "", "/", "/subdir_with_space ", dirPerms, "0", "0", 0L));
            }
            rootDirTuples.add(tuple("testfile.txt", false, "txt", "/", "/testfile.txt", filePerms, "0", "0", 15L));
            testFilesInDir(fileAbstractor, "/", rootDirTuples.toArray(new Tuple[0]));

            testFilesInDir(fileAbstractor, "/nested",
                    tuple("buzz", true, "", "/nested", "/nested/buzz", dirPerms, "0", "0", 0L),
                    tuple("foo.txt", false, "txt", "/nested", "/nested/foo.txt", filePerms, "0", "0", 24L),
                    tuple("bar.txt", false, "txt", "/nested", "/nested/bar.txt", filePerms, "0", "0", 8L));
            testFilesInDir(fileAbstractor, "/permission",
                    tuple("all.txt", false, "txt", "/permission", "/permission/all.txt", allPerms, "0", "0", 3L),
                    tuple("none.txt", false, "txt", "/permission", "/permission/none.txt", nonePerms, "0", "0", 3L));
            // This test case is skipped on Windows because its filesystem does not support
            // directory names with trailing spaces.
            if (!OsValidator.WINDOWS) {
                testFilesInDir(fileAbstractor, "/subdir_with_space ",
                        tuple("hello.txt", false, "txt", "/subdir_with_space ", "/subdir_with_space /hello.txt", filePerms, "0", "0", 33L),
                        tuple("world.txt", false, "txt", "/subdir_with_space ", "/subdir_with_space /world.txt", filePerms, "0", "0", 33L));
            }
        }

        // --- Second run: Test with PEM file (passwordless authentication) ---
        fsSettings.getServer().setPemPath(rootTmpDir.resolve("private.key").toString());
        fsSettings.getServer().setPassword(null);
        try (FileAbstractor<?> fileAbstractor = new FileAbstractorSSH(fsSettings)) {
            fileAbstractor.open();
            assertThat(fileAbstractor.exists("/ThisPathDoesNotExist")).isFalse();
            testFilesInDir(fileAbstractor, "/ThisPathDoesNotExist");

            java.util.List<Tuple> rootDirTuples = new ArrayList<>();
            rootDirTuples.add(tuple("nested", true, "", "/", "/nested", dirPerms, "0", "0", 0L));
            rootDirTuples.add(tuple("permission", true, "", "/", "/permission", dirPerms, "0", "0", 0L));
            // This test case is skipped on Windows because its filesystem does not support
            // directory names with trailing spaces.
            if (!OsValidator.WINDOWS) {
                rootDirTuples.add(tuple("subdir_with_space ", true, "", "/", "/subdir_with_space ", dirPerms, "0", "0", 0L));
            }
            rootDirTuples.add(tuple("testfile.txt", false, "txt", "/", "/testfile.txt", filePerms, "0", "0", 15L));
            testFilesInDir(fileAbstractor, "/", rootDirTuples.toArray(new Tuple[0]));

            testFilesInDir(fileAbstractor, "/nested",
                    tuple("buzz", true, "", "/nested", "/nested/buzz", dirPerms, "0", "0", 0L),
                    tuple("foo.txt", false, "txt", "/nested", "/nested/foo.txt", filePerms, "0", "0", 24L),
                    tuple("bar.txt", false, "txt", "/nested", "/nested/bar.txt", filePerms, "0", "0", 8L));
            testFilesInDir(fileAbstractor, "/permission",
                    tuple("all.txt", false, "txt", "/permission", "/permission/all.txt", allPerms, "0", "0", 3L),
                    tuple("none.txt", false, "txt", "/permission", "/permission/none.txt", nonePerms, "0", "0", 3L));
            // This test case is skipped on Windows because its filesystem does not support
            // directory names with trailing spaces.
            if (!OsValidator.WINDOWS) {
                testFilesInDir(fileAbstractor, "/subdir_with_space ",
                        tuple("hello.txt", false, "txt", "/subdir_with_space ", "/subdir_with_space /hello.txt", filePerms, "0", "0", 33L),
                        tuple("world.txt", false, "txt", "/subdir_with_space ", "/subdir_with_space /world.txt", filePerms, "0", "0", 33L));
            }
        }
    }

    /**
     * A powerful helper method to assert the contents of a given directory on the remote server.
     * It's designed to be robust across different operating systems by handling OS-specific behaviors.
     * @param fileAbstractor The abstractor instance to use.
     * @param path The remote directory path to list and check.
     * @param values The expected file/directory attributes (as Tuples) in that directory.
     */
    private void testFilesInDir(FileAbstractor<?> fileAbstractor, String path, Tuple... values) throws Exception {
        assertThat(fileAbstractor.exists(path)).isEqualTo(values.length > 0);
        Collection<FileAbstractModel> models = fileAbstractor.getFiles(path);
        assertThat(models).hasSize(values.length);

        // We can't assert on the size of a directory as it depends on the OS (e.g., 0 on Windows, 4096 on Linux).
        // So we split our assertions for files and directories to handle this case.

        // 1. Assertions for files
        assertThat(models.stream().filter(FileAbstractModel::isFile).collect(Collectors.toList())).extracting(
                FileAbstractModel::getName,
                FileAbstractModel::isDirectory,
                FileAbstractModel::getExtension,
                FileAbstractModel::getPath,
                FileAbstractModel::getFullpath,
                FileAbstractModel::getPermissions,
                FileAbstractModel::getOwner,
                FileAbstractModel::getGroup,
                FileAbstractModel::getSize
        ).containsExactlyInAnyOrder(
                java.util.stream.Stream.of(values).filter(tuple -> !(boolean) tuple.toList().get(1)).toArray(Tuple[]::new)
        );

        // 2. Assertions for directories: We specifically DO NOT extract the size, making the test OS-independent.
        assertThat(models.stream().filter(FileAbstractModel::isDirectory).collect(Collectors.toList())).extracting(
                FileAbstractModel::getName,
                FileAbstractModel::isDirectory,
                FileAbstractModel::getExtension,
                FileAbstractModel::getPath,
                FileAbstractModel::getFullpath,
                FileAbstractModel::getPermissions,
                FileAbstractModel::getOwner,
                FileAbstractModel::getGroup
                ).containsExactlyInAnyOrder(
                java.util.stream.Stream.of(values)
                        .filter(tuple -> (boolean) tuple.toList().get(1))
                        // From the original 9-element test tuples, create new 8-element tuples that match the properties
                        // being extracted for directories (omitting size).
                        .map(tuple -> tuple(tuple.toList().get(0), tuple.toList().get(1), tuple.toList().get(2), tuple.toList().get(3),
                                tuple.toList().get(4), tuple.toList().get(5), tuple.toList().get(6), tuple.toList().get(7)))
                        .toArray(Tuple[]::new)
        );
    }

    /**
     * Helper to create a file with specific content in a given directory.
     */
    private void addFakeFile(Path dir, String filename, String content) throws IOException {
        Path testFile = dir.resolve(filename);
        if (Files.notExists(testFile)) {
            Files.writeString(testFile, content);
        }
    }

    /**
     * Helper to create a subdirectory.
     */
    private Path addFakeDir(Path dir, String subDirname) throws IOException {
        Path testDir = dir.resolve(subDirname);
        if (Files.notExists(testDir)) {
            Files.createDirectory(testDir);
        }
        return testDir;
    }
}
