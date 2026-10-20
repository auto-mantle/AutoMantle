package com.automantle.api.config;

import com.zaxxer.hikari.HikariDataSource;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.sqlite.SQLiteConfig;
import org.sqlite.SQLiteDataSource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;

import javax.sql.DataSource;

@Configuration
public class DatabaseConfig {
    private static final String DATABASE_FILENAME = "automantle.sqlite";
    private static final int SQLITE_BUSY_TIMEOUT_MILLIS = 5000;
    private static final long CONNECTION_TIMEOUT_MILLIS = 30_000;

    @Bean
    @DependsOn("entityManagerFactory")
    InitializingBean localSchema(DataSource dataSource) {
        return () -> {
            try (var connection = dataSource.getConnection();
                    var statement = connection.createStatement()) {
                statement.execute(
                        "CREATE INDEX IF NOT EXISTS agent_rule_profile ON"
                                + " agent_rule(agent_profile_id)");
                statement.execute(
                        "CREATE UNIQUE INDEX IF NOT EXISTS request_history_request_id ON"
                                + " request_history(request_id)");
                statement.execute(
                        "CREATE INDEX IF NOT EXISTS request_history_profile_id ON"
                                + " request_history(agent_profile_id, id)");
                statement.execute(
                        "CREATE INDEX IF NOT EXISTS request_history_created_at ON"
                                + " request_history(created_at)");
            }
        };
    }

    @Bean(destroyMethod = "close")
    HikariDataSource dataSource(@Value("${app.database.directory}") String directory)
            throws IOException {
        Path path = Path.of(directory).toAbsolutePath().normalize();
        if (path.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            Files.createDirectories(
                    path,
                    PosixFilePermissions.asFileAttribute(
                            PosixFilePermissions.fromString("rwx------")));
        } else {
            Files.createDirectories(path);
        }
        var config = new SQLiteConfig();
        config.enforceForeignKeys(true);
        config.setBusyTimeout(SQLITE_BUSY_TIMEOUT_MILLIS);
        config.setJournalMode(SQLiteConfig.JournalMode.WAL);
        config.setSynchronous(SQLiteConfig.SynchronousMode.FULL);
        var sqlite = new SQLiteDataSource(config);
        sqlite.setUrl("jdbc:sqlite:" + path.resolve(DATABASE_FILENAME));
        var pool = new HikariDataSource();
        pool.setDataSource(sqlite);
        pool.setMaximumPoolSize(1);
        pool.setMinimumIdle(1);
        pool.setConnectionTimeout(CONNECTION_TIMEOUT_MILLIS);
        return pool;
    }
}
