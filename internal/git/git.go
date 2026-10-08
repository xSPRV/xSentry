package git

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func OpenRepository(path string) (*git.Repository, error) {
	repo, err := git.PlainOpen(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open git repository at path '%s': %w", path, err)
	}

	return repo, nil
}

func IsShallowRepository(repo *git.Repository) (bool, error) {
	shallowCommits, err := repo.Storer.Shallow()
	if err != nil {
		return false, fmt.Errorf("failed to read shallow repository metadata: %w", err)
	}
	return len(shallowCommits) > 0, nil
}

func GetHeadPatch(repo *git.Repository) (string, error) {
	headRef, err := repo.Head()
	if err != nil {
		return "", fmt.Errorf("failed to get HEAD ref: %w", err)
	}

	commit, err := repo.CommitObject(headRef.Hash())
	if err != nil {
		return "", fmt.Errorf("failed to get commit object: %w", err)
	}

	var parent *object.Commit
	if commit.NumParents() > 0 {
		parent, err = commit.Parent(0)
		if err != nil {
			return "", fmt.Errorf("failed to get parent commit: %w", err)
		}
	}

	patch, err := commit.Patch(parent)
	if err != nil {
		return "", fmt.Errorf("failed to generate patch: %w", err)
	}

	return patch.String(), nil
}

type CommitPatch struct {
	Hash  string
	Patch string
}

func ForEachCommitPatch(repo *git.Repository, visit func(CommitPatch) error) error {
	cIter, err := repo.Log(&git.LogOptions{
		Order: git.LogOrderCommitterTime,
	})

	if err != nil {
		return fmt.Errorf("failed to get commit log: %w", err)
	}

	err = cIter.ForEach(func(c *object.Commit) error {
		var parent *object.Commit
		if c.NumParents() > 0 {
			parent, err = c.Parent(0)
			if err != nil {
				return fmt.Errorf("failed to get parent for commit %s: %w", c.Hash, err)
			}
		}

		patch, err := c.Patch(parent)
		if err != nil {
			return fmt.Errorf("failed to generate patch for commit %s: %w", c.Hash, err)
		}
		if err := visit(CommitPatch{Hash: c.Hash.String(), Patch: patch.String()}); err != nil {
			return fmt.Errorf("failed to process commit %s: %w", c.Hash, err)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed while walking commit history: %w", err)
	}
	return nil
}

func GetStagedPatch() (string, error) {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return "", fmt.Errorf("git executable not found in PATH")
	}

	cmd := exec.Command(gitPath, "diff", "--staged", "--diff-filter=ACMRTUXB")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to run 'git diff --staged': %v\nOutput: %s", err, string(output))
	}

	return string(output), nil
}

// GetRangePatch returns the diff of changes introduced by headRef relative to
// the merge base of baseRef and headRef. This is useful for scanning a PR or
// push without rescanning the repository's entire history.
func GetRangePatch(repoPath, baseRef, headRef string) (string, error) {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return "", fmt.Errorf("git executable not found in PATH")
	}
	baseHash, err := resolveCommit(gitPath, repoPath, baseRef)
	if err != nil {
		return "", fmt.Errorf("could not resolve base commit %q: %w", baseRef, err)
	}
	headHash, err := resolveCommit(gitPath, repoPath, headRef)
	if err != nil {
		return "", fmt.Errorf("could not resolve head commit %q: %w", headRef, err)
	}

	cmd := exec.Command(gitPath, "-C", repoPath, "diff", "--no-ext-diff", "--unified=0", baseHash+"..."+headHash, "--")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to run git diff for %q...%q: %v\nOutput: %s", baseRef, headRef, err, string(output))
	}
	return string(output), nil
}

func resolveCommit(gitPath, repoPath, ref string) (string, error) {
	cmd := exec.Command(gitPath, "-C", repoPath, "rev-parse", "--verify", "--end-of-options", ref+"^{commit}")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git rev-parse failed: %v\nOutput: %s", err, string(output))
	}
	return strings.TrimSpace(string(output)), nil
}
