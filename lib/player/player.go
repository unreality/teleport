/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

// Package player includes an API to play back recorded sessions.
package player

import (
	"context"
	"errors"
	"math"
	"sync/atomic"
	"time"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/sirupsen/logrus"

	"github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/lib/session"
)

// Player is used to stream recorded sessions over a channel.
type Player struct {
	// read only config fields
	clock     clockwork.Clock
	log       logrus.FieldLogger
	sessionID session.ID
	streamer  Streamer

	speed      atomic.Value // playback speed (1.0 for normal speed)
	lastPlayed atomic.Int64 // timestamp of most recently played event

	// advanceTo is used to implement fast-forward and rewind.
	// During normal operation, it is set to [normalPlayback].
	//
	// When set to a positive value the player is seeking forward
	// in time (and plays events as quickly as possible).
	//
	// When set to a negative value, the player needs to "rewind"
	// by starting the stream over from the beginning and then
	// seeking forward to the rewind point.
	advanceTo atomic.Int64

	emit chan events.AuditEvent
	done chan struct{}

	// playPause holds a channel to be closed when
	// the player transitions from paused to playing,
	// or nil if the player is already playing.
	//
	// This approach mimics a "select-able" condition variable
	// and is inspired by "Rethinking Classical Concurrency Patterns"
	// by Bryan C. Mills (GopherCon 2018): https://www.youtube.com/watch?v=5zXAHh5tJqQ
	playPause chan chan struct{}

	// err holds the error (if any) encountered during playback
	err error
}

const normalPlayback = math.MinInt64

// Streamer is the underlying streamer that provides
// access to recorded session events.
type Streamer interface {
	StreamSessionEvents(
		ctx context.Context,
		sessionID session.ID,
		startIndex int64,
	) (chan events.AuditEvent, chan error)
}

// Config configures a session player.
type Config struct {
	Clock     clockwork.Clock
	Log       logrus.FieldLogger
	SessionID session.ID
	Streamer  Streamer
}

func New(cfg *Config) (*Player, error) {
	if cfg.Streamer == nil {
		return nil, trace.BadParameter("missing Streamer")
	}

	if cfg.SessionID == "" {
		return nil, trace.BadParameter("missing SessionID")
	}

	clk := cfg.Clock
	if clk == nil {
		clk = clockwork.NewRealClock()
	}

	var log logrus.FieldLogger = cfg.Log
	if log == nil {
		log = logrus.New().WithField(trace.Component, "player")
	}

	p := &Player{
		clock:     clk,
		log:       log,
		sessionID: cfg.SessionID,
		streamer:  cfg.Streamer,
		emit:      make(chan events.AuditEvent, 1024),
		playPause: make(chan chan struct{}, 1),
		done:      make(chan struct{}),
	}

	p.speed.Store(float64(defaultPlaybackSpeed))
	p.advanceTo.Store(normalPlayback)

	// start in a paused state
	p.playPause <- make(chan struct{})

	go p.stream()

	return p, nil
}

// errClosed is an internal error that is used to signal
// that the player has been closed
var errClosed = errors.New("player closed")

const (
	minPlaybackSpeed     = 0.25
	defaultPlaybackSpeed = 1.0
	maxPlaybackSpeed     = 16
)

// SetSpeed adjusts the playback speed of the player.
// It can be called at any time (the player can be in a playing
// or paused state). A speed of 1.0 plays back at regular speed,
// while a speed of 2.0 plays back twice as fast as originally
// recorded. Valid speeds range from 0.25 to 16.0.
func (p *Player) SetSpeed(s float64) error {
	if s < minPlaybackSpeed || s > maxPlaybackSpeed {
		return trace.BadParameter("speed %v is out of range", s)
	}
	p.speed.Store(s)
	return nil
}

func (p *Player) stream() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	eventsC, errC := p.streamer.StreamSessionEvents(ctx, p.sessionID, 0)
	lastDelay := int64(0)
	for {
		select {
		case <-p.done:
			close(p.emit)
			return
		case err := <-errC:
			p.log.Warn(err)
			p.err = err
			close(p.emit)
			return
		case evt := <-eventsC:
			if evt == nil {
				p.log.Debugf("reached end of playback for session %v", p.sessionID)
				close(p.emit)
				return
			}

			if err := p.waitWhilePaused(); err != nil {
				p.log.Warn(err)
				close(p.emit)
				return
			}

			currentDelay := getDelay(evt)
			if currentDelay > 0 && currentDelay >= lastDelay {
				switch adv := p.advanceTo.Load(); {
				case adv >= currentDelay:
					// no timing delay necessary, we are fast forwarding
					break
				case adv < 0 && adv != normalPlayback:
					// any negative value other than normalPlayback means
					// we rewind (by restarting the stream and seeking forward
					// to the rewind point)
					p.advanceTo.Store(adv * -1)
					go p.stream()
					return
				default:
					if adv != normalPlayback {
						p.advanceTo.Store(normalPlayback)

						// we're catching back up to real time, so the delay
						// is calculated not from the last event but from the
						// time we were advanced to
						lastDelay = adv
					}
					if err := p.applyDelay(time.Duration(currentDelay-lastDelay) * time.Millisecond); err != nil {
						close(p.emit)
						return
					}
				}

				lastDelay = currentDelay
			}

			// if the receiver can't keep up, let the channel throttle us
			// (it's better for playback to be a little slower than realtime
			// than to drop events)
			//
			// TODO: consider a select with a timeout to detect blocked readers?
			p.emit <- evt
			p.lastPlayed.Store(currentDelay)
		}
	}
}

// Close shuts down the player and cancels any streams that are
// in progress.
func (p *Player) Close() error {
	close(p.done)
	return nil
}

// C returns a read only channel of recorded session events.
// The player manages the timing of events and writes them to the channel
// when they should be rendered. The channel is closed when the player
// has reached the end of playback.
func (p *Player) C() <-chan events.AuditEvent {
	return p.emit
}

// Err returns the error (if any) that occurred during playback.
// It should only be called after the channel returned by [C] is
// closed.
func (p *Player) Err() error {
	return p.err
}

// Pause temporarily stops the player from emitting events.
// It is a no-op if playback is currently paused.
func (p *Player) Pause() error {
	p.setPlaying(false)
	return nil
}

// Play starts emitting events. It is used to start playback
// for the first time and to resume playing after the player
// is paused.
func (p *Player) Play() error {
	p.setPlaying(true)
	return nil
}

// SetPos sets playback to a specific time, expressed as a duration
// from the beginning of the session. A duration of 0 restarts playback
// from the beginning. A duration greater than the length of the session
// will cause playback to rapidly advance to the end of the recording.
func (p *Player) SetPos(d time.Duration) error {
	if d.Milliseconds() < p.lastPlayed.Load() {
		// if we're rewinding we store a negative value
		d = -1 * d
	}
	p.advanceTo.Store(d.Milliseconds())
	return nil
}

// applyDelay "sleeps" for d in a manner that
// can be canceled
func (p *Player) applyDelay(d time.Duration) error {
	scaled := float64(d) / p.speed.Load().(float64)
	select {
	case <-p.done:
		return errClosed
	case <-p.clock.After(time.Duration(scaled)):
		return nil
	}
}

func (p *Player) setPlaying(play bool) {
	ch := <-p.playPause
	alreadyPlaying := ch == nil

	if alreadyPlaying && !play {
		ch = make(chan struct{})
	} else if !alreadyPlaying && play {
		// signal waiters who are paused that it's time to resume playing
		close(ch)
		ch = nil
	}

	p.playPause <- ch
}

// waitWhilePaused blocks while the player is in a paused state.
// It returns immediately if the player is currently playing.
func (p *Player) waitWhilePaused() error {
	ch := <-p.playPause
	p.playPause <- ch

	if alreadyPlaying := ch == nil; !alreadyPlaying {
		select {
		case <-p.done:
			return errClosed
		case <-ch:
		}
	}
	return nil
}

// LastPlayed returns the time of the last played event,
// expressed as milliseconds since the start of the session.
func (p *Player) LastPlayed() int64 {
	return p.lastPlayed.Load()
}

func getDelay(e events.AuditEvent) int64 {
	switch x := e.(type) {
	case *events.DesktopRecording:
		return x.DelayMilliseconds
	case *events.SessionPrint:
		return x.DelayMilliseconds
	default:
		return int64(0)
	}
}
