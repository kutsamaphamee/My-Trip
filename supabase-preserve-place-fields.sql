-- MY TRIP: preserve Google Maps URLs and estimated place costs
alter table public.places
  add column if not exists url text,
  add column if not exists estimated_cost numeric not null default 0;

alter table public.restaurants
  add column if not exists url text;

-- Keep existing RLS policies in place. These tables already use user_id ownership policies.
