package Apache2::AuthenMobileJP;

use strict;
use warnings;
our $VERSION = '0.01';

use Apache2::Module;
use Apache2::Access ();
use Apache2::Log;
use Apache2::Connection () ;
use Apache2::CmdParms ();
use Apache2::ServerUtil;
use Apache2::RequestUtil ();
use Apache2::RequestRec;
use Apache2::Const -compile => qw(OK DECLINED NO_ARGS TAKE1 TAKE2 TAKE3
			NOT_FOUND HTTP_FORBIDDEN HTTP_UNAUTHORIZED);
use Net::CIDR::MobileJP;
use HTTP::MobileAgent;
use HTTP::MobileAttribute plugins => [
    qw/
        CIDR
        IS
        UserID
    /
];

my $cidr = Net::CIDR::MobileJP->new();
# register myself to apache
{
    my @directives = (
        {
            name		=> 'AuthMobileJPAllowUser',
            args_how	=> Apache2::Const::TAKE1,
            errmsg		=> 'AuthMobileJPAllowUser User',
        },
    );
    Apache2::Module::add(__PACKAGE__, \@directives);
    Apache2::ServerUtil->server->push_handlers( PerlAuthenHandler => __PACKAGE__ ); 
}

# callback from apache in awesome phase
sub handler :method {
    my ($class, $r) = @_;
    lc($r->auth_type) eq 'mobilejp' or return Apache2::Const::DECLINED;

    # my $ua = $r->headers_in->{'User-Agent'};
    # my $ma = HTTP::MobileAgent->new();
    my $ma = HTTP::MobileAttribute->new($r->headers_in);
    $r->server->log_error($ma);
    $r->server->log_error($class);
    if ($ma->is_ezweb || $ma->is_docomo || $ma->is_softbank) {
        $r->server->log_error("mobile");
        $ma->user_id or return Apache2::Const::HTTP_FORBIDDEN; # no user id?
        # $cidr->get_carrier() eq $ma->carrier or return Apache2::Const::HTTP_FORBIDDEN; # valid ip?
        $ma->isa_cidr($r->connection->remote_ip) or return Apache2::Const::HTTP_FORBIDDEN; # valid ip?

        # OK!
        $r->server->log_error("OK");
        $r->user($ma->user_id);
        return Apache2::Const::OK;
    } else {
        return Apache2::Const::HTTP_FORBIDDEN;
    }
}

1;
__END__

=head1 NAME

Apache2::AuthenMobileJP -

=head1 SYNOPSIS

  use Apache2::AuthenMobileJP;

=head1 DESCRIPTION

tekitou auth.

some code is taken from Apache2::AuthEnv.

=head1 AUTHOR

Tokuhiro Matsuno E<lt>tokuhirom jsdfkla gmail fsadkjl comE<gt>

=head1 THANKS TO

Anthony R Fletcher - author of Apache2::AuthEnv

=head1 SEE ALSO

L<Apache2::AuthEnv>

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
