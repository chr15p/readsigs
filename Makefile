# fctool - manage fc devices 
#
# Copyright (C) 2010 Chris Procter
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions
# of the GNU General Public License v.2.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

BIN=readsigs
SRC=readsigs.go

all: build


build: 
	go build -o $(BIN) $(SRC)

clean:
	rm $(BIN)
