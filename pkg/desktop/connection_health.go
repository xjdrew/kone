package desktop

import (
	"errors"
	"github.com/xjdrew/kone/pkg/kone"
	"time"
)

type healthOwner interface {
	HealthData(kone.HealthQuery) (kone.HealthState, error)
	HealthAction(kone.HealthAction) (kone.HealthIncident, error)
}

func (s *helperService) Health(q kone.HealthQuery, reply *kone.HealthState) error {
	engine, err := s.current()
	if err != nil {
		return err
	}
	owner, ok := engine.(healthOwner)
	if !ok {
		return errors.New("health unavailable")
	}
	*reply, err = owner.HealthData(q)
	return err
}
func (s *helperService) HealthAction(a kone.HealthAction, reply *kone.HealthIncident) error {
	engine, err := s.current()
	if err != nil {
		return err
	}
	owner, ok := engine.(healthOwner)
	if !ok {
		return errors.New("health unavailable")
	}
	*reply, err = owner.HealthAction(a)
	return err
}
func (e *RemoteEngine) HealthData(q kone.HealthQuery) (kone.HealthState, error) {
	var reply kone.HealthState
	err := e.call("Health", q, &reply, 3*time.Second)
	return reply, err
}
func (e *RemoteEngine) HealthAction(a kone.HealthAction) (kone.HealthIncident, error) {
	var reply kone.HealthIncident
	err := e.call("HealthAction", a, &reply, 10*time.Second)
	return reply, err
}
