package se.portvakt.sdk;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

/** A clock tests can move: the real time plus an offset. */
final class MutableClock extends Clock {
  private volatile Duration offset = Duration.ZERO;

  void advance(Duration duration) {
    offset = offset.plus(duration);
  }

  @Override
  public ZoneId getZone() {
    return ZoneOffset.UTC;
  }

  @Override
  public Clock withZone(ZoneId zone) {
    return this;
  }

  @Override
  public Instant instant() {
    return Instant.now().plus(offset);
  }
}
