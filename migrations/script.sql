create table refresh_tokens
(
    id            serial,
    refresh_token text not null
);

alter table refresh_tokens
    owner to postgres;

alter table refresh_tokens
    add constraint refresh_tokens_pk
        primary key (id);


