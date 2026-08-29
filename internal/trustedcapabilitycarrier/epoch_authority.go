package trustedcapabilitycarrier

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

type FileEpochAuthority struct {
	root   string
	lock   *os.File
	mu     sync.Mutex
	states map[string]sourceState
}

type sourceState struct {
	Generation uint64 `json:"generation"`
	Sequence   uint64 `json:"sequence"`
	Commitment []byte `json:"commitment"`
}

func OpenFileEpochAuthority(root string) (*FileEpochAuthority, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errors.New("Carrier epoch authority path must be absolute and clean")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	lock, err := acquireStoreLock(root)
	if err != nil {
		return nil, err
	}
	authority := &FileEpochAuthority{root: root, lock: lock, states: map[string]sourceState{}}
	raw, err := os.ReadFile(filepath.Join(root, "source-epochs.json"))
	if err == nil {
		if json.Unmarshal(raw, &authority.states) != nil || authority.states == nil {
			_ = releaseStoreLock(lock)
			return nil, errors.New("Carrier epoch authority is corrupt")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		_ = releaseStoreLock(lock)
		return nil, err
	}
	return authority, nil
}

func (authority *FileEpochAuthority) Close() error {
	if authority == nil || authority.lock == nil {
		return nil
	}
	err := releaseStoreLock(authority.lock)
	authority.lock = nil
	return err
}

func (authority *FileEpochAuthority) CheckSourceState(_ context.Context, carrierID string, generation, sequence uint64, commitment []byte) error {
	if carrierID == "" || generation == 0 || len(commitment) != 32 {
		return errors.New("Carrier source state is incomplete")
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	prior, exists := authority.states[carrierID]
	if exists && generation < prior.Generation {
		return errors.New("Carrier source generation rollback")
	}
	if exists && generation == prior.Generation {
		if sequence < prior.Sequence || sequence > prior.Sequence+1 {
			return errors.New("Carrier source sequence rollback or gap")
		}
		if sequence == prior.Sequence {
			if !bytes.Equal(commitment, prior.Commitment) {
				return errors.New("Carrier source state equivocation")
			}
			return nil
		}
	}
	// A generation advance is the explicit recovery boundary and may retain a
	// snapshot at any sequence. Within one generation advancement is exactly
	// one contiguous sequence at a time.
	authority.states[carrierID] = sourceState{Generation: generation, Sequence: sequence, Commitment: append([]byte(nil), commitment...)}
	raw, err := json.MarshalIndent(authority.states, "", "  ")
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(authority.root, ".epochs-")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name)
	if err = temp.Chmod(0o600); err == nil {
		_, err = temp.Write(append(raw, '\n'))
	}
	if err == nil {
		err = temp.Sync()
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(name, filepath.Join(authority.root, "source-epochs.json"))
	}
	if err != nil {
		if exists {
			authority.states[carrierID] = prior
		} else {
			delete(authority.states, carrierID)
		}
		return err
	}
	directory, err := os.Open(authority.root)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
