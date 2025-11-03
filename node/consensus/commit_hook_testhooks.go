//go:build testhooks

package consensus

var commitTestHook func(stage string)

func invokeCommitHook(stage string) {
	if commitTestHook != nil {
		commitTestHook(stage)
	}
}
