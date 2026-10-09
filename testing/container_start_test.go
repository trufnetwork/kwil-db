package testing

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeDockerScript stands in for docker, so the container start can be tested
// without Docker. It records every call. Its "logs --follow" prints the lines
// Postgres prints while it initializes, except that for the first
// $FAKE_DOCKER_STALLS calls it stops after the first line and keeps the stream
// open, which is how a container that never reports ready looks. While the file
// "conflict" exists, "run" fails the way docker does when a container of the
// same name is left over, and "rm" removes that leftover.
const fakeDockerScript = `#!/bin/sh
echo "$*" >> "$FAKE_DOCKER_DIR/calls"
case "$1" in
run)
	if [ -f "$FAKE_DOCKER_DIR/conflict" ]; then
		echo 'docker: Error response from daemon: Conflict. The container name "/kwil-testing-postgres" is already in use by container "0123abcd".' >&2
		exit 125
	fi
	echo "fake-container-id"
	;;
rm)
	rm -f "$FAKE_DOCKER_DIR/conflict"
	;;
logs)
	if [ "$2" = "--tail" ]; then
		echo "last line from the stalled container"
		exit 0
	fi
	n=$(cat "$FAKE_DOCKER_DIR/follows" 2>/dev/null || echo 0)
	n=$((n + 1))
	echo "$n" > "$FAKE_DOCKER_DIR/follows"
	echo "LOG:  database system is ready to accept connections"
	if [ "$n" -gt "$FAKE_DOCKER_STALLS" ]; then
		echo "LOG:  database system is shut down"
		echo "PostgreSQL init process complete; ready for start up."
	fi
	exec sleep 30
	;;
esac
`

// useFakeDocker puts fakeDockerScript first on PATH, with its first stalls
// containers never reporting ready, and shortens containerStartTimeout so a
// stalled container costs two seconds. It returns the script's directory and a
// func that lists the docker calls made so far.
func useFakeDocker(t *testing.T, stalls int) (string, func() []string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the docker stand-in is a shell script")
	}

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "docker"), []byte(fakeDockerScript), 0o755))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_DOCKER_DIR", dir)
	t.Setenv("FAKE_DOCKER_STALLS", strconv.Itoa(stalls))

	prev := containerStartTimeout
	containerStartTimeout = 2 * time.Second
	t.Cleanup(func() { containerStartTimeout = prev })

	return dir, func() []string {
		b, err := os.ReadFile(filepath.Join(dir, "calls"))
		require.NoError(t, err)
		return strings.Split(strings.TrimSpace(string(b)), "\n")
	}
}

type captureLogger struct{ lines []string }

func (c *captureLogger) Logf(format string, args ...any) {
	c.lines = append(c.lines, fmt.Sprintf(format, args...))
}

var (
	runCall    = strings.Join(dockerStartArgs("52853"), " ")
	followCall = "logs --follow " + ContainerName
	tailCall   = "logs --tail 50 " + ContainerName
	removeCall = "rm -f -v " + ContainerName
)

func TestStartTestContainer(t *testing.T) {
	t.Run("returns once the container reports ready", func(t *testing.T) {
		_, calls := useFakeDocker(t, 0)
		logger := &captureLogger{}

		out, err := startTestContainer(context.Background(), &Options{Logger: logger}, "52853")

		require.NoError(t, err)
		assert.Equal(t, "fake-container-id\n", string(out))
		assert.Equal(t, []string{runCall, followCall}, calls())
		assert.Empty(t, logger.lines)
	})

	t.Run("replaces a container that never reports ready", func(t *testing.T) {
		_, calls := useFakeDocker(t, 1)
		logger := &captureLogger{}

		out, err := startTestContainer(context.Background(), &Options{Logger: logger}, "52853")

		require.NoError(t, err)
		assert.Equal(t, "fake-container-id\n", string(out))
		assert.Equal(t, []string{runCall, followCall, tailCall, removeCall, runCall, followCall}, calls())
		require.Len(t, logger.lines, 1)
		assert.Contains(t, logger.lines[0], "attempt 1 of 2")
		assert.Contains(t, logger.lines[0], context.DeadlineExceeded.Error())
		assert.Contains(t, logger.lines[0], "last line from the stalled container")
	})

	t.Run("gives up after a second container never reports ready", func(t *testing.T) {
		_, calls := useFakeDocker(t, 2)
		logger := &captureLogger{}
		start := time.Now()

		_, err := startTestContainer(context.Background(), &Options{Logger: logger}, "52853")

		require.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Contains(t, err.Error(), "error waiting for logs")
		assert.Less(t, time.Since(start), 10*time.Second)
		// Both stalled containers are removed, so none is left to block the next start.
		assert.Equal(t, []string{runCall, followCall, tailCall, removeCall, runCall, followCall, tailCall, removeCall}, calls())
		assert.Len(t, logger.lines, 2)
	})

	t.Run("stops retrying when the caller's context ends", func(t *testing.T) {
		_, calls := useFakeDocker(t, 2)
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()

		_, err := startTestContainer(ctx, &Options{Logger: &captureLogger{}}, "52853")

		// The error is the wait's, not a failed attempt to start another container,
		// and the stalled container is still removed.
		require.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Contains(t, err.Error(), "error waiting for logs")
		assert.Equal(t, []string{runCall, followCall, tailCall, removeCall}, calls())
	})
}

func TestRunTestContainer(t *testing.T) {
	leaveContainer := func(t *testing.T, dir string) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "conflict"), nil, 0o644))
	}

	t.Run("replaces a leftover container when the caller agrees", func(t *testing.T) {
		dir, calls := useFakeDocker(t, 0)
		leaveContainer(t, dir)
		asked := 0
		opts := &Options{ReplaceExistingContainer: func() (bool, error) { asked++; return true, nil }}

		out, err := runTestContainer(context.Background(), opts, "52853")

		require.NoError(t, err)
		assert.Equal(t, "fake-container-id\n", string(out))
		assert.Equal(t, 1, asked)
		assert.Equal(t, []string{runCall, removeCall, runCall}, calls())
	})

	t.Run("keeps a leftover container when the caller declines", func(t *testing.T) {
		dir, calls := useFakeDocker(t, 0)
		leaveContainer(t, dir)
		opts := &Options{ReplaceExistingContainer: func() (bool, error) { return false, nil }}

		_, err := runTestContainer(context.Background(), opts, "52853")

		require.ErrorContains(t, err, "conflicting container name")
		assert.Equal(t, []string{runCall}, calls())
	})

	t.Run("fails on a leftover container when no callback is set", func(t *testing.T) {
		dir, calls := useFakeDocker(t, 0)
		leaveContainer(t, dir)

		_, err := runTestContainer(context.Background(), &Options{}, "52853")

		require.ErrorContains(t, err, "failed to get output from container")
		assert.Equal(t, []string{runCall}, calls())
	})

	t.Run("says so when docker is not installed", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())

		_, err := runTestContainer(context.Background(), &Options{}, "52853")

		require.ErrorContains(t, err, "docker not found")
	})
}
