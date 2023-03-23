package utils

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	gssh "github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"golang.org/x/crypto/ssh"
)

func CloneGit(repoURL, repoPath, privateKey, branchName string) (*object.Commit, error) {

	_, err := os.Stat(privateKey)
	if err != nil {
		err := fmt.Errorf("read file %s failed %s", privateKey, err.Error())
		return nil, err
	}

	publicKeys, err := gssh.NewPublicKeysFromFile("git", privateKey, "")

	if err != nil {
		err := fmt.Errorf("generate publickeys failed: %s", err.Error())
		return nil, err
	} else {
		publicKeys.HostKeyCallbackHelper = gssh.HostKeyCallbackHelper{
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}
	}

	branch := fmt.Sprintf("refs/heads/%s", branchName)
	repo, err := git.PlainClone(repoPath, false, &git.CloneOptions{
		Auth:          publicKeys,
		URL:           repoURL,
		ReferenceName: plumbing.ReferenceName(branch),
	})
	if err != nil {
		err := fmt.Errorf("unable to clone repo: %s", err.Error())
		return nil, err
	}

	// Print the latest commit that was just pulled
	ref, err := repo.Head()
	if err != nil {
		err := fmt.Errorf("unable to access git head: %s", err.Error())
		return nil, err
	}

	commit, err := repo.CommitObject(ref.Hash())
	if err != nil {
		err := fmt.Errorf("unable to get commit hash: %s", err.Error())
		return nil, err
	}

	return commit, err
}

func PullGit(repoPath, privateKey, branchName string) (*object.Commit, error) {

	_, err := os.Stat(privateKey)
	if err != nil {
		err := fmt.Errorf("read file %s failed %s", privateKey, err.Error())
		return nil, err
	}

	publicKeys, err := gssh.NewPublicKeysFromFile("git", privateKey, "")

	if err != nil {
		err := fmt.Errorf("generate publickeys failed: %s", err.Error())
		return nil, err
	}

	// We instantiate a new repository targeting the given path (the .git folder)
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		err := fmt.Errorf("opening git repo failed: %s", err.Error())
		return nil, err
	}
	// Get the working directory for the repository
	w, err := repo.Worktree()
	if err != nil {
		err := fmt.Errorf("getting git working directory failed: %s", err.Error())
		return nil, err
	}
	branch := fmt.Sprintf("refs/heads/%s", branchName)
	if err = w.Pull(&git.PullOptions{
		ReferenceName: plumbing.ReferenceName(branch),
		SingleBranch:  true,
		Force:         true,
		Auth:          publicKeys,
	}); err != nil && err != git.NoErrAlreadyUpToDate {
		return nil, err
	}

	// Print the latest commit that was just pulled
	ref, err := repo.Head()
	if err != nil {
		err := fmt.Errorf("unable to access git head: %s", err.Error())
		return nil, err
	}

	commit, err := repo.CommitObject(ref.Hash())
	if err != nil {
		err := fmt.Errorf("unable to get commit hash: %s", err.Error())
		return nil, err
	}

	return commit, err
}

// MakeED25519KeyPair make a pair of public and private keys for SSH access.
func MakeED25519KeyPair(privateKeyPath string) error {
	_, fileCheck := os.Stat(privateKeyPath)
	if fileCheck == nil {
		return nil
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	// generate and write private key as PEM
	privateKeyFile, err := os.Create(privateKeyPath)
	if err != nil {
		return err
	}
	defer privateKeyFile.Close()
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey) // Convert a generated ed25519 key into a PEM block so that the ssh library can ingest it, bit round about tbh
	if err != nil {
		return err
	}

	privateKeyPEM := &pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes}
	if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
		return err
	}

	// generate and write public key
	pub, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(privateKeyPath+".pub", ssh.MarshalAuthorizedKey(pub), 0655)
}
