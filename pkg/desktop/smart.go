package desktop

import (
	"errors"
	"github.com/xjdrew/kone/pkg/kone"
	"time"
)

type smartOwner interface {
	SmartData() (kone.SmartState, error)
	SmartAction(kone.SmartAction) (kone.SmartActionResult, error)
}

func (s *helperService) Smart(_ Empty, reply *kone.SmartState) error {
	engine, err := s.current()
	if err != nil {
		return err
	}
	owner, ok := engine.(smartOwner)
	if !ok {
		return errors.New("Smart unavailable in helper")
	}
	*reply, err = owner.SmartData()
	return err
}
func (s *helperService) SmartAction(request kone.SmartAction, reply *kone.SmartActionResult) error {
	engine, err := s.current()
	if err != nil {
		return err
	}
	owner, ok := engine.(smartOwner)
	if !ok {
		return errors.New("Smart unavailable in helper")
	}
	*reply, err = owner.SmartAction(request)
	return err
}
func (e *RemoteEngine) SmartData() (kone.SmartState, error) {
	var reply kone.SmartState
	err := e.call("Smart", Empty{}, &reply, 3*time.Second)
	return reply, err
}
func (e *RemoteEngine) SmartAction(request kone.SmartAction) (kone.SmartActionResult, error) {
	var reply kone.SmartActionResult
	err := e.call("SmartAction", request, &reply, 20*time.Second)
	return reply, err
}
