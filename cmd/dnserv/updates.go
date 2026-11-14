package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/prezmc/dnserv/internal/cluster"
	"github.com/prezmc/dnserv/internal/store"
	"github.com/prezmc/dnserv/internal/update"
)

// clusterPeers lets the update rollout reach the other nodes.
type clusterPeers struct {
	cl *cluster.Cluster
	st *store.Store
}

func (p clusterPeers) Self() string { return p.cl.ID() }

func (p clusterPeers) Members() []update.Member {
	leader := p.cl.LocalStatus().LeaderID
	var out []update.Member
	for id, n := range p.st.State().Cluster.Nodes {
		out = append(out, update.Member{ID: id, Name: n.Name, Leader: id == leader, Witness: n.Witness})
	}
	return out
}

func (p clusterPeers) Ask(ctx context.Context, id, rpc string, in any) (json.RawMessage, error) {
	return p.cl.AskPeer(ctx, id, rpc, in)
}

// newUpdates sets up update checks and installs for a node or witness,
// and answers the other nodes' update calls.
func newUpdates(cl *cluster.Cluster, st *store.Store, dataDir string, ready func() bool, loc func() *time.Location, log *slog.Logger) *update.Manager {
	m := &update.Manager{
		Version:  version,
		Registry: registryFromEnv(),
		Sidecar:  update.NewClient(envOr("DNSERV_UPDATER_SOCKET", update.SocketPath)),
		Image:    envOr("DNSERV_UPDATE_IMAGE", update.DefaultImage),
		Ready:    ready,
		Location: loc,
		Peers:    clusterPeers{cl: cl, st: st},
		Prefs: func() update.Prefs {
			p := st.State().Updates
			return update.Prefs{Check: !p.NoCheck, Auto: p.Auto, AutoHour: p.AutoHour, Skip: p.Skip}
		},
		Audit: func(by, revision string, servers []string, auto, rollback bool) {
			if _, err := cl.Propose(store.NewCommand(store.OpUpdateStart, by, store.UpdateStart{Revision: revision, Servers: servers, Auto: auto, Rollback: rollback})); err != nil {
				log.Warn("couldn't record the update in the audit log", "err", err)
			}
		},
		SetSkip: func(by, revision string) {
			if _, err := cl.Propose(store.NewCommand(store.OpUpdateSkip, by, store.UpdateSkip{Revision: revision})); err != nil {
				log.Warn("couldn't record the skipped version", "err", err)
			}
		},
		StateFile: filepath.Join(dataDir, "update-rollout.json"),
		Log:       log.With("component", "update"),
	}
	cl.Handle(update.RPCInfo, m.HandleInfo)
	cl.Handle(update.RPCStart, m.HandleStart)
	return m
}

// runUpdater runs the updater container (dnserv -updater). See
// internal/update/sidecar.go for what it may and may not do.
func runUpdater(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	s := &update.Sidecar{
		Docker:  update.NewDocker(envOr("DOCKER_SOCKET", "/var/run/docker.sock")),
		Version: version,
		Target:  os.Getenv("DNSERV_UPDATER_TARGET"),
		Log:     log.With("component", "updater"),
	}
	st := s.Status(ctx)
	if st.Error != "" {
		log.Warn("updater can't see its DNServ container yet", "err", st.Error)
	} else {
		log.Info("updater looking after", "container", st.Target, "image", st.Image)
	}
	// 65532 is the dnserv user and group in the image.
	return s.Serve(ctx, envOr("DNSERV_UPDATER_SOCKET", update.SocketPath), 65532, 65532)
}

// registryFromEnv reads DNSERV_UPDATE_REGISTRY: a registry to ask instead
// of the one in the image name, as host:port, or http://host:port for one
// without HTTPS (a test lab).
func registryFromEnv() *update.Registry {
	r := &update.Registry{}
	v := os.Getenv("DNSERV_UPDATE_REGISTRY")
	switch {
	case strings.HasPrefix(v, "http://"):
		r.Scheme, r.Host = "http", strings.TrimPrefix(v, "http://")
	case strings.HasPrefix(v, "https://"):
		r.Host = strings.TrimPrefix(v, "https://")
	default:
		r.Host = v
	}
	return r
}
