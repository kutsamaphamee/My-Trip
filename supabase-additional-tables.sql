-- MY TRIP: additional tables for Transportation and Accommodation
-- Run this script in Supabase SQL Editor for the my-trip project.

create table if not exists public.transportation (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  trip_id uuid references public.trips(id) on delete cascade,
  kind text,
  name text not null,
  travel_datetime timestamp without time zone,
  booking_reference text,
  created_at timestamptz not null default now()
);

create table if not exists public.accommodation (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  trip_id uuid references public.trips(id) on delete cascade,
  name text not null,
  address text,
  check_in date,
  check_out date,
  booking_reference text,
  cost numeric not null default 0,
  created_at timestamptz not null default now()
);

alter table public.transportation enable row level security;
alter table public.accommodation enable row level security;

drop policy if exists "Users manage own transportation" on public.transportation;
create policy "Users manage own transportation"
on public.transportation
for all
to authenticated
using (auth.uid() = user_id)
with check (auth.uid() = user_id);

drop policy if exists "Users manage own accommodation" on public.accommodation;
create policy "Users manage own accommodation"
on public.accommodation
for all
to authenticated
using (auth.uid() = user_id)
with check (auth.uid() = user_id);

create index if not exists transportation_user_trip_idx
  on public.transportation(user_id, trip_id);
create index if not exists accommodation_user_trip_idx
  on public.accommodation(user_id, trip_id);
