-- One row per command invocation that mutates.
create table ops(
  id integer primary key,
  op_id text not null unique,
  started_at text not null,
  finished_at text,
  command text not null,
  args text not null,
  source text not null check (source in ('cli','tui','web','backfill')),
  os_user text,
  machine text,
  version text,
  result text check (result in ('ok','error','aborted','dry-run')),
  error text,
  snapshot text,
  manifest_before text,
  manifest_after text,
  inventory_before text,
  inventory_after text
);

-- Every log.Audit event, plus the ones backfilled from what was on disk.
create table events(
  id integer primary key,
  op_id text references ops(op_id),
  ts text not null,
  event text not null,
  fields text not null,
  source text not null,
  dedupe text unique
);

-- The names an event or operation is about, for the --host/--profile/--key filters.
create table subjects(
  event_id integer references events(id),
  op_id text references ops(op_id),
  kind text not null check (kind in ('profile','host','key','target')),
  name text not null
);

-- Content-addressed manifest copies, so an operation can show what it changed.
create table manifests(
  sha text primary key,
  captured_at text not null,
  body blob not null
);

create table meta(key text primary key, value text not null);

create index events_ts on events(ts);
create index events_op on events(op_id);
create index subjects_kind_name on subjects(kind, name);
create index ops_started on ops(started_at);
